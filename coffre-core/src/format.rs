//! File format v1: fixed binary header (authenticated as AAD) and deterministic
//! payload serialization.

use std::collections::BTreeMap;

use zeroize::Zeroize;

use crate::crypto::{NONCE_LEN, SALT_LEN};

/// Magic bytes at the start of the file.
pub const MAGIC: [u8; 8] = *b"COFFRE\0\0";
/// Supported format version.
pub const VERSION: u16 = 1;
/// Key derivation algorithm identifier (Argon2id).
pub const KDF_ARGON2ID: u8 = 1;
/// Header size, in bytes.
pub const HEADER_LEN: usize = 79;

/// Secret table: name to binary value.
pub type Entries = BTreeMap<String, Vec<u8>>;

/// Format read/write error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatError {
    /// Data too short for a valid header or payload.
    TooShort,
    /// Invalid magic bytes.
    BadMagic,
    /// Unsupported format version.
    UnsupportedVersion(u16),
    /// Unsupported key derivation algorithm.
    UnsupportedKdf(u8),
    /// Non-UTF-8 entry name.
    InvalidUtf8,
    /// Duplicate entry name.
    DuplicateName,
    /// Length exceeds `u32`.
    LengthOverflow,
    /// Trailing bytes after the payload.
    TrailingData,
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatError::TooShort => write!(f, "data too short"),
            FormatError::BadMagic => write!(f, "bad magic bytes"),
            FormatError::UnsupportedVersion(version) => {
                write!(f, "unsupported format version: {version}")
            }
            FormatError::UnsupportedKdf(kdf_id) => {
                write!(f, "unsupported key derivation algorithm: {kdf_id}")
            }
            FormatError::InvalidUtf8 => write!(f, "invalid UTF-8 secret name"),
            FormatError::DuplicateName => write!(f, "duplicate secret name"),
            FormatError::LengthOverflow => write!(f, "length overflow"),
            FormatError::TrailingData => write!(f, "trailing data after payload"),
        }
    }
}

impl std::error::Error for FormatError {}

/// File header, in clear text and authenticated as AAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Format version.
    pub version: u16,
    /// Key derivation algorithm identifier.
    pub kdf_id: u8,
    /// Argon2 memory cost, in KiB.
    pub m_cost: u32,
    /// Argon2 number of passes.
    pub t_cost: u32,
    /// Argon2 parallelism.
    pub p_cost: u32,
    /// Argon2 salt.
    pub salt: [u8; SALT_LEN],
    /// XChaCha20 nonce.
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    /// Serializes the header into `HEADER_LEN` bytes (big-endian).
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..8].copy_from_slice(&MAGIC);
        out[8..10].copy_from_slice(&self.version.to_be_bytes());
        out[10] = self.kdf_id;
        out[11..15].copy_from_slice(&self.m_cost.to_be_bytes());
        out[15..19].copy_from_slice(&self.t_cost.to_be_bytes());
        out[19..23].copy_from_slice(&self.p_cost.to_be_bytes());
        out[23..55].copy_from_slice(&self.salt);
        out[55..79].copy_from_slice(&self.nonce);
        out
    }

    /// Reads and validates a header.
    ///
    /// Never panics, even on arbitrary input: the header is read before
    /// authentication, so it is exposed to untrusted data.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() < HEADER_LEN {
            return Err(FormatError::TooShort);
        }
        if &bytes[0..8] != MAGIC.as_slice() {
            return Err(FormatError::BadMagic);
        }
        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if version != VERSION {
            return Err(FormatError::UnsupportedVersion(version));
        }
        let kdf_id = bytes[10];
        if kdf_id != KDF_ARGON2ID {
            return Err(FormatError::UnsupportedKdf(kdf_id));
        }
        let m_cost = u32::from_be_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]);
        let t_cost = u32::from_be_bytes([bytes[15], bytes[16], bytes[17], bytes[18]]);
        let p_cost = u32::from_be_bytes([bytes[19], bytes[20], bytes[21], bytes[22]]);
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[23..55]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[55..79]);
        Ok(Self {
            version,
            kdf_id,
            m_cost,
            t_cost,
            p_cost,
            salt,
            nonce,
        })
    }
}

/// Serializes entries into a deterministic binary payload.
///
/// Order follows `BTreeMap` (sorted by name), so the same content always produces
/// the same bytes. The exact size is computed up front to avoid reallocations,
/// which would leave copies of the plaintext in memory.
pub fn encode_payload(entries: &Entries) -> Result<Vec<u8>, FormatError> {
    let count = u32::try_from(entries.len()).map_err(|_| FormatError::LengthOverflow)?;
    let mut size = 4usize;
    for (name, value) in entries {
        size = size
            .checked_add(4)
            .and_then(|s| s.checked_add(name.len()))
            .and_then(|s| s.checked_add(4))
            .and_then(|s| s.checked_add(value.len()))
            .ok_or(FormatError::LengthOverflow)?;
    }
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&count.to_be_bytes());
    for (name, value) in entries {
        let name_len = u32::try_from(name.len()).map_err(|_| FormatError::LengthOverflow)?;
        let value_len = u32::try_from(value.len()).map_err(|_| FormatError::LengthOverflow)?;
        out.extend_from_slice(&name_len.to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&value_len.to_be_bytes());
        out.extend_from_slice(value);
    }
    Ok(out)
}

/// Deserializes a payload.
///
/// Never panics: any invalid input (truncated, overflowing length, invalid UTF-8,
/// duplicate, trailing bytes) returns an error. On error, already-decoded entries
/// are zeroized.
pub fn decode_payload(bytes: &[u8]) -> Result<Entries, FormatError> {
    let mut entries = Entries::new();
    match decode_payload_into(bytes, &mut entries) {
        Ok(()) => Ok(entries),
        Err(e) => {
            zeroize_entries(&mut entries);
            Err(e)
        }
    }
}

fn decode_payload_into(bytes: &[u8], entries: &mut Entries) -> Result<(), FormatError> {
    let mut pos = 0usize;
    let count = read_u32(bytes, &mut pos)?;
    for _ in 0..count {
        let name_len = read_u32(bytes, &mut pos)? as usize;
        let name_bytes = take(bytes, &mut pos, name_len)?;
        let name = std::str::from_utf8(name_bytes).map_err(|_| FormatError::InvalidUtf8)?;
        let value_len = read_u32(bytes, &mut pos)? as usize;
        let value = take(bytes, &mut pos, value_len)?;
        if entries.contains_key(name) {
            return Err(FormatError::DuplicateName);
        }
        // Allocate only after the entry is validated: no plaintext copy is
        // abandoned without zeroization on an error path.
        entries.insert(name.to_owned(), value.to_vec());
    }
    if pos != bytes.len() {
        return Err(FormatError::TrailingData);
    }
    Ok(())
}

fn zeroize_entries(entries: &mut Entries) {
    let drained = std::mem::take(entries);
    for (mut name, mut value) in drained {
        name.zeroize();
        value.zeroize();
    }
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, FormatError> {
    let end = pos.checked_add(4).ok_or(FormatError::TooShort)?;
    let slice = bytes.get(*pos..end).ok_or(FormatError::TooShort)?;
    *pos = end;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn take<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], FormatError> {
    let end = pos.checked_add(len).ok_or(FormatError::TooShort)?;
    let slice = bytes.get(*pos..end).ok_or(FormatError::TooShort)?;
    *pos = end;
    Ok(slice)
}
