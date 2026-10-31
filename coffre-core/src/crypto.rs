//! Primitives cryptographiques : dérivation de clé (Argon2id) et AEAD XChaCha20-Poly1305.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

/// Longueur de la clé AEAD, en octets (256 bits).
pub const KEY_LEN: usize = 32;
/// Longueur du sel Argon2, en octets.
pub const SALT_LEN: usize = 32;
/// Longueur du nonce XChaCha20, en octets (192 bits).
pub const NONCE_LEN: usize = 24;
/// Longueur du tag d'authentification Poly1305, en octets.
pub const TAG_LEN: usize = 16;

/// Erreur cryptographique.
///
/// Volontairement grossière : un mauvais mot de passe et des données corrompues
/// produisent la même erreur, pour ne pas fournir d'oracle à un attaquant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// La dérivation de clé a échoué (paramètres invalides).
    KeyDerivation,
    /// Le chiffrement a échoué.
    Encryption,
    /// Le déchiffrement a échoué : tag invalide.
    Decryption,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::KeyDerivation => write!(f, "key derivation failed"),
            CryptoError::Encryption => write!(f, "encryption failed"),
            CryptoError::Decryption => write!(f, "wrong passphrase or corrupted data"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Paramètres de coût d'Argon2id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Coût mémoire, en KiB.
    pub m_cost: u32,
    /// Nombre de passes.
    pub t_cost: u32,
    /// Degré de parallélisme.
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// Dérive une clé de 256 bits depuis la phrase secrète et le sel.
///
/// Déterministe : les mêmes `(passphrase, salt, params)` produisent la même clé.
/// Le sel doit être unique par coffre ; il n'a pas besoin d'être secret.
pub fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<[u8; KEY_LEN], CryptoError> {
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| CryptoError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

/// Chiffre et authentifie `plaintext` avec XChaCha20-Poly1305.
///
/// `aad` est authentifié mais non chiffré : toute altération de `aad` fait échouer
/// le déchiffrement. Le `nonce` doit être unique pour chaque appel sous une même clé.
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encryption)
}

/// Vérifie le tag et déchiffre `ciphertext`.
///
/// Échoue si la clé, le nonce, l'AAD ou le ciphertext diffèrent de ceux utilisés
/// au chiffrement.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decryption)
}
