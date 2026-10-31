//! Vault lifecycle: creation, opening, atomic saving and zeroization.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, CryptoError, KEY_LEN, KdfParams, NONCE_LEN, SALT_LEN};
use crate::format::{self, Entries, FormatError, HEADER_LEN, Header, KDF_ARGON2ID, VERSION};

const MAX_M_COST: u32 = 524_288;
const MAX_T_COST: u32 = 10;
const MAX_P_COST: u32 = 16;

/// Vault layer error.
#[derive(Debug)]
#[non_exhaustive]
pub enum VaultError {
    /// Input/output error.
    Io(std::io::Error),
    /// File format error.
    Format(FormatError),
    /// Cryptographic error.
    Crypto(CryptoError),
    /// The file already exists (creation refused to avoid overwriting).
    AlreadyExists,
    /// Argon2 parameters out of bounds (anti-DoS protection).
    UnsupportedParams,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(e) => write!(f, "io: {e}"),
            VaultError::Format(e) => write!(f, "format: {e}"),
            VaultError::Crypto(e) => write!(f, "{e}"),
            VaultError::AlreadyExists => write!(f, "vault already exists"),
            VaultError::UnsupportedParams => write!(f, "unsupported kdf parameters"),
        }
    }
}

impl std::error::Error for VaultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VaultError::Io(e) => Some(e),
            VaultError::Format(e) => Some(e),
            VaultError::Crypto(e) => Some(e),
            VaultError::AlreadyExists | VaultError::UnsupportedParams => None,
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}

impl From<FormatError> for VaultError {
    fn from(e: FormatError) -> Self {
        VaultError::Format(e)
    }
}

impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        VaultError::Crypto(e)
    }
}

fn rng_fill(buf: &mut [u8]) -> Result<(), VaultError> {
    getrandom::fill(buf).map_err(|e| VaultError::Io(std::io::Error::other(e.to_string())))
}

/// An open vault, held in memory.
///
/// Secrets are decrypted in memory for the session. Mutations (`add`, `remove`)
/// are only persisted on the next [`Vault::save`] call.
///
/// The type deliberately does not implement `Debug`, to avoid exposing the key or
/// secrets in a log.
pub struct Vault {
    path: PathBuf,
    header: Header,
    key: Zeroizing<[u8; KEY_LEN]>,
    entries: Entries,
}

impl Vault {
    /// Creates a new vault at `path`.
    ///
    /// Fails if the file already exists. A random salt is generated, the key is
    /// derived, then an empty vault is written with `create_new`. Creation cannot
    /// overwrite an existing file, even under a race between processes.
    pub fn create(path: &Path, passphrase: &[u8], params: KdfParams) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let mut salt = [0u8; SALT_LEN];
        rng_fill(&mut salt)?;
        let header = Header {
            version: VERSION,
            kdf_id: KDF_ARGON2ID,
            m_cost: params.m_cost,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
            salt,
            nonce: [0u8; NONCE_LEN],
        };
        Self::check_params(&header)?;
        let key = Zeroizing::new(crypto::derive_key(passphrase, &salt, &params)?);
        let mut vault = Self {
            path: path.to_path_buf(),
            header,
            key,
            entries: Entries::new(),
        };
        let bytes = vault.serialize()?;
        write_exclusive(&vault.path, &bytes)?;
        Ok(vault)
    }

    /// Opens and decrypts an existing vault.
    ///
    /// Argon2 parameters read from the header are bounded before derivation
    /// (protection against a crafted file). A wrong passphrase and a corrupted file
    /// produce the same error.
    pub fn open(path: &Path, passphrase: &[u8]) -> Result<Self, VaultError> {
        let bytes = fs::read(path)?;
        if bytes.len() < HEADER_LEN {
            return Err(FormatError::TooShort.into());
        }
        let (header_bytes, body) = bytes.split_at(HEADER_LEN);
        let header = Header::decode(header_bytes)?;
        Self::check_params(&header)?;
        let params = KdfParams {
            m_cost: header.m_cost,
            t_cost: header.t_cost,
            p_cost: header.p_cost,
        };
        let key = Zeroizing::new(crypto::derive_key(passphrase, &header.salt, &params)?);
        let plaintext = Zeroizing::new(crypto::open(&key, header.nonce, body, header_bytes)?);
        let entries = format::decode_payload(plaintext.as_slice())?;
        Ok(Self {
            path: path.to_path_buf(),
            header,
            key,
            entries,
        })
    }

    /// Atomically rewrites the vault on disk.
    ///
    /// A new nonce is generated on every call. The write goes through a temporary
    /// file (`fsync`) then a `rename`, followed by a directory `fsync`.
    pub fn save(&mut self) -> Result<(), VaultError> {
        let bytes = self.serialize()?;
        write_atomic(&self.path, &bytes)
    }

    /// Adds or replaces a secret in memory. Not persisted before `save`.
    pub fn add(&mut self, name: &str, value: &[u8]) {
        if let Some(mut old) = self.entries.insert(name.to_owned(), value.to_vec()) {
            old.zeroize();
        }
    }

    /// Reads a secret from memory.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.entries.get(name).map(Vec::as_slice)
    }

    /// Lists secret names, sorted.
    pub fn list(&self) -> impl Iterator<Item = &str> + '_ {
        self.entries.keys().map(String::as_str)
    }

    /// Removes a secret from memory. Returns `true` if it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        match self.entries.remove(name) {
            Some(mut value) => {
                value.zeroize();
                true
            }
            None => false,
        }
    }

    /// Path of the vault file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn serialize(&mut self) -> Result<Vec<u8>, VaultError> {
        let mut nonce = [0u8; NONCE_LEN];
        rng_fill(&mut nonce)?;
        self.header.nonce = nonce;
        let header_bytes = self.header.encode();
        let plaintext = Zeroizing::new(format::encode_payload(&self.entries)?);
        let body = crypto::seal(&self.key, nonce, plaintext.as_slice(), &header_bytes)?;

        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&body);
        Ok(out)
    }

    fn check_params(header: &Header) -> Result<(), VaultError> {
        let sane = header.m_cost <= MAX_M_COST
            && header.t_cost >= 1
            && header.t_cost <= MAX_T_COST
            && header.p_cost >= 1
            && header.p_cost <= MAX_P_COST
            // Argon2 minimum; p_cost is already bounded, so no overflow.
            && header.m_cost >= 8 * header.p_cost;
        if sane {
            Ok(())
        } else {
            Err(VaultError::UnsupportedParams)
        }
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        let entries = std::mem::take(&mut self.entries);
        for (mut name, mut value) in entries {
            name.zeroize();
            value.zeroize();
        }
    }
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn open_new(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn write_and_sync(mut file: File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()
}

fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(dir_handle) = File::open(dir) {
        let _ = dir_handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Writes a new file without ever overwriting an existing one (`create_new`).
///
/// No temporary file or hard link: this also works on filesystems that do not
/// support hard links (FAT, exFAT, network shares). On write failure, the partial
/// file is removed.
fn write_exclusive(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let file = match open_new(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(VaultError::AlreadyExists);
        }
        Err(e) => return Err(VaultError::Io(e)),
    };
    if let Err(e) = write_and_sync(file, bytes) {
        let _ = fs::remove_file(path);
        return Err(VaultError::Io(e));
    }
    sync_dir(parent_dir(path));
    Ok(())
}

/// Atomically replaces `path`: temporary file (`fsync`), `rename`, then a
/// directory `fsync`.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let dir = parent_dir(path);
    let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid vault path",
        ))
    })?;

    let mut suffix = [0u8; 8];
    rng_fill(&mut suffix)?;
    let tmp = dir.join(format!(
        ".{file_name}.tmp.{:016x}",
        u64::from_le_bytes(suffix)
    ));

    if let Err(e) = open_new(&tmp).and_then(|file| write_and_sync(file, bytes)) {
        let _ = fs::remove_file(&tmp);
        return Err(VaultError::Io(e));
    }

    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(VaultError::Io(e));
    }

    sync_dir(dir);
    Ok(())
}
