//! Format de fichier v1 : en-tête binaire fixe (authentifié comme AAD) et
//! sérialisation déterministe du payload.

use std::collections::BTreeMap;

use crate::crypto::{NONCE_LEN, SALT_LEN};

/// Octets magiques en tête de fichier.
pub const MAGIC: [u8; 8] = *b"COFFRE\0\0";
/// Version du format supportée.
pub const VERSION: u16 = 1;
/// Identifiant de l'algorithme de dérivation de clé (Argon2id).
pub const KDF_ARGON2ID: u8 = 1;
/// Taille de l'en-tête, en octets.
pub const HEADER_LEN: usize = 79;

/// Table des secrets : nom vers valeur binaire.
pub type Entries = BTreeMap<String, Vec<u8>>;

/// Erreur de lecture ou d'écriture du format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// Données trop courtes pour un en-tête ou un payload valide.
    TooShort,
    /// Octets magiques invalides.
    BadMagic,
    /// Version de format non supportée.
    UnsupportedVersion(u16),
    /// Algorithme de dérivation de clé non supporté.
    UnsupportedKdf(u8),
    /// Nom d'entrée non UTF-8.
    InvalidUtf8,
    /// Nom d'entrée en double.
    DuplicateName,
    /// Longueur dépassant `u32`.
    LengthOverflow,
    /// Octets résiduels après le payload.
    TrailingData,
}

/// En-tête de fichier, en clair et authentifié comme AAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Version du format.
    pub version: u16,
    /// Identifiant de l'algorithme de dérivation de clé.
    pub kdf_id: u8,
    /// Coût mémoire Argon2, en KiB.
    pub m_cost: u32,
    /// Nombre de passes Argon2.
    pub t_cost: u32,
    /// Parallélisme Argon2.
    pub p_cost: u32,
    /// Sel Argon2.
    pub salt: [u8; SALT_LEN],
    /// Nonce XChaCha20.
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    /// Sérialise l'en-tête sur `HEADER_LEN` octets (big-endian).
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

    /// Lit et valide un en-tête.
    ///
    /// Ne panique jamais, même sur une entrée arbitraire : l'en-tête est lu avant
    /// l'authentification, il est donc exposé à des données non fiables.
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

/// Sérialise les entrées en un payload binaire déterministe.
///
/// L'ordre est celui de `BTreeMap` (trié par nom), donc un même contenu produit
/// toujours les mêmes octets.
pub fn encode_payload(entries: &Entries) -> Result<Vec<u8>, FormatError> {
    let count = u32::try_from(entries.len()).map_err(|_| FormatError::LengthOverflow)?;
    let mut out = Vec::new();
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

/// Désérialise un payload.
///
/// Ne panique jamais : toute entrée invalide (tronquée, longueur débordante,
/// UTF-8 invalide, doublon, octets en trop) renvoie une erreur.
pub fn decode_payload(bytes: &[u8]) -> Result<Entries, FormatError> {
    let mut pos = 0usize;
    let count = read_u32(bytes, &mut pos)?;
    let mut entries = Entries::new();
    for _ in 0..count {
        let name_len = read_u32(bytes, &mut pos)? as usize;
        let name_bytes = take(bytes, &mut pos, name_len)?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| FormatError::InvalidUtf8)?
            .to_owned();
        let value_len = read_u32(bytes, &mut pos)? as usize;
        let value = take(bytes, &mut pos, value_len)?.to_vec();
        if entries.insert(name, value).is_some() {
            return Err(FormatError::DuplicateName);
        }
    }
    if pos != bytes.len() {
        return Err(FormatError::TrailingData);
    }
    Ok(entries)
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
