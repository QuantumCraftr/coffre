//! Cycle de vie du coffre : création, ouverture, sauvegarde atomique et zeroization.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, CryptoError, KEY_LEN, KdfParams, NONCE_LEN, SALT_LEN};
use crate::format::{self, Entries, FormatError, HEADER_LEN, Header, KDF_ARGON2ID, VERSION};

const MAX_M_COST: u32 = 524_288;
const MAX_T_COST: u32 = 10;
const MAX_P_COST: u32 = 16;

/// Erreur de la couche coffre.
#[derive(Debug)]
#[non_exhaustive]
pub enum VaultError {
    /// Erreur d'entrée/sortie.
    Io(std::io::Error),
    /// Erreur de format de fichier.
    Format(FormatError),
    /// Erreur cryptographique.
    Crypto(CryptoError),
    /// Le fichier existe déjà (création refusée pour ne pas écraser).
    AlreadyExists,
    /// Paramètres Argon2 hors bornes (protection anti-DoS).
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

/// Un coffre ouvert en mémoire.
///
/// Les secrets sont déchiffrés en mémoire pendant la session. Les mutations
/// (`add`, `remove`) ne sont persistées qu'au prochain appel à [`Vault::save`].
///
/// Le type n'implémente volontairement pas `Debug`, pour ne pas risquer d'exposer
/// la clé ou les secrets dans un log.
pub struct Vault {
    path: PathBuf,
    header: Header,
    key: Zeroizing<[u8; KEY_LEN]>,
    entries: Entries,
}

impl Vault {
    /// Crée un nouveau coffre à `path`.
    ///
    /// Échoue si le fichier existe déjà. Un sel aléatoire est généré, la clé est
    /// dérivée, puis un coffre vide est écrit avec `create_new`. La création ne
    /// peut pas écraser un fichier existant, même en cas de course entre processus.
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

    /// Ouvre et déchiffre un coffre existant.
    ///
    /// Les paramètres Argon2 lus dans l'en-tête sont bornés avant dérivation
    /// (protection contre un fichier piégé). Un mauvais mot de passe et un fichier
    /// corrompu produisent la même erreur.
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

    /// Réécrit le coffre sur disque de façon atomique.
    ///
    /// Un nouveau nonce est généré à chaque appel. L'écriture passe par un fichier
    /// temporaire (`fsync`) puis un `rename`, suivi d'un `fsync` du dossier.
    pub fn save(&mut self) -> Result<(), VaultError> {
        let bytes = self.serialize()?;
        write_atomic(&self.path, &bytes)
    }

    /// Ajoute ou remplace un secret en mémoire. Non persisté avant `save`.
    pub fn add(&mut self, name: &str, value: &[u8]) {
        if let Some(mut old) = self.entries.insert(name.to_owned(), value.to_vec()) {
            old.zeroize();
        }
    }

    /// Lit un secret en mémoire.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.entries.get(name).map(Vec::as_slice)
    }

    /// Liste les noms de secrets, triés.
    pub fn list(&self) -> impl Iterator<Item = &str> + '_ {
        self.entries.keys().map(String::as_str)
    }

    /// Supprime un secret en mémoire. Renvoie `true` s'il existait.
    pub fn remove(&mut self, name: &str) -> bool {
        match self.entries.remove(name) {
            Some(mut value) => {
                value.zeroize();
                true
            }
            None => false,
        }
    }

    /// Chemin du fichier de coffre.
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
            // Minimum imposé par Argon2 ; p_cost est déjà borné, pas de débordement.
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

/// Écrit un nouveau fichier sans jamais écraser l'existant (`create_new`).
///
/// Pas de fichier temporaire ni de lien physique : fonctionne aussi sur les
/// systèmes de fichiers qui ne supportent pas les hard links (FAT, exFAT, partages
/// réseau). En cas d'échec d'écriture, le fichier partiel est supprimé.
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

/// Remplace `path` de façon atomique : fichier temporaire (`fsync`), `rename`,
/// puis `fsync` du dossier.
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
