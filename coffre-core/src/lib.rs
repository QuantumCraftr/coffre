//! Coeur du coffre : format de fichier, chiffrement et cycle de vie.
//!
//! Bibliothèque du binaire `coffre`. Aucune I/O réseau, aucun service externe.

#![warn(missing_docs)]

pub mod crypto;
pub mod format;
pub mod vault;

/// Version du crate, issue de `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
