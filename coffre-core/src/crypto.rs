use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    KeyDerivation,
    Encryption,
    Decryption,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
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
