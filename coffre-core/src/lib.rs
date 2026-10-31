//! Coffre core: file format, encryption and lifecycle.
//!
//! Library for the `coffre` binary. No network I/O, no external service.

#![warn(missing_docs)]

pub mod crypto;
pub mod format;
pub mod vault;

/// Crate version, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
