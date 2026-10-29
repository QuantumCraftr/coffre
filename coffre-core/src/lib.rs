//! Coeur du coffre : format de fichier, chiffrement, zeroization.

pub mod crypto;
pub mod format;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
