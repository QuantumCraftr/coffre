//! Cryptographic primitives: Argon2id key derivation and XChaCha20-Poly1305 AEAD.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

/// AEAD key length, in bytes (256 bits).
pub const KEY_LEN: usize = 32;
/// Argon2 salt length, in bytes.
pub const SALT_LEN: usize = 32;
/// XChaCha20 nonce length, in bytes (192 bits).
pub const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length, in bytes.
pub const TAG_LEN: usize = 16;

/// Cryptographic error.
///
/// Deliberately coarse: a wrong passphrase and corrupted data produce the same
/// error, so an attacker gets no oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// Key derivation failed (invalid parameters).
    KeyDerivation,
    /// Encryption failed.
    Encryption,
    /// Decryption failed: invalid tag.
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

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost, in KiB.
    pub m_cost: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism.
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

/// Derives a 256-bit key from the passphrase and salt.
///
/// Deterministic: the same `(passphrase, salt, params)` produce the same key.
/// The salt must be unique per vault; it does not need to be secret.
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

/// Encrypts and authenticates `plaintext` with XChaCha20-Poly1305.
///
/// `aad` is authenticated but not encrypted: any change to `aad` makes decryption
/// fail. The `nonce` must be unique for every call under the same key.
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

/// Verifies the tag and decrypts `ciphertext`.
///
/// Fails if the key, nonce, AAD or ciphertext differ from those used for encryption.
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
