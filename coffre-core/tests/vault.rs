use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use coffre_core::crypto::KdfParams;
use coffre_core::format::{HEADER_LEN, Header, KDF_ARGON2ID, VERSION};
use coffre_core::vault::{Vault, VaultError};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("coffre-test-{}-{}", std::process::id(), n));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn vault_path(&self) -> PathBuf {
        self.0.join("vault.coffre")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn test_params() -> KdfParams {
    KdfParams {
        m_cost: 32,
        t_cost: 1,
        p_cost: 1,
    }
}

fn read_header(path: &std::path::Path) -> Header {
    let bytes = fs::read(path).unwrap();
    Header::decode(&bytes[..HEADER_LEN]).unwrap()
}

fn expect_err(result: Result<Vault, VaultError>) -> VaultError {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

#[test]
fn create_and_open_round_trip() {
    let tmp = TempDir::new();
    let path = tmp.vault_path();
    {
        let mut vault = Vault::create(&path, b"pass", test_params()).unwrap();
        vault.add("db", b"postgres://x");
        vault.add("token", b"secret");
        vault.save().unwrap();
    }
    let vault = Vault::open(&path, b"pass").unwrap();
    assert_eq!(vault.get("db"), Some(&b"postgres://x"[..]));
    assert_eq!(vault.get("token"), Some(&b"secret"[..]));
    assert_eq!(vault.list().collect::<Vec<_>>(), vec!["db", "token"]);
}

#[test]
fn save_persists_new_entries() {
    let tmp = TempDir::new();
    let path = tmp.vault_path();
    let mut vault = Vault::create(&path, b"pass", test_params()).unwrap();
    vault.add("a", b"1");
    vault.save().unwrap();
    vault.add("b", b"2");
    vault.save().unwrap();
    drop(vault);
    let vault = Vault::open(&path, b"pass").unwrap();
    assert_eq!(vault.get("a"), Some(&b"1"[..]));
    assert_eq!(vault.get("b"), Some(&b"2"[..]));
}

#[test]
fn remove_entry() {
    let tmp = TempDir::new();
    let path = tmp.vault_path();
    let mut vault = Vault::create(&path, b"pass", test_params()).unwrap();
    vault.add("a", b"1");
    assert!(vault.remove("a"));
    assert!(!vault.remove("a"));
    assert_eq!(vault.get("a"), None);
}

#[test]
fn wrong_passphrase_fails() {
    let tmp = TempDir::new();
    let path = tmp.vault_path();
    Vault::create(&path, b"correct", test_params()).unwrap();
    let err = expect_err(Vault::open(&path, b"wrong"));
    assert!(matches!(err, VaultError::Crypto(_)));
}

#[test]
fn corrupted_body_fails() {
    let tmp = TempDir::new();
    let path = tmp.vault_path();
    Vault::create(&path, b"pass", test_params()).unwrap();
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&path, &bytes).unwrap();
    assert!(Vault::open(&path, b"pass").is_err());
}

#[test]
fn tampered_salt_fails() {
    let tmp = TempDir::new();
    let path = tmp.vault_path();
    Vault::create(&path, b"pass", test_params()).unwrap();
    let mut bytes = fs::read(&path).unwrap();
    // Modifier le sel change la clé dérivée et l'AAD : le tag doit échouer.
    bytes[23] ^= 1;
    fs::write(&path, &bytes).unwrap();
    let err = expect_err(Vault::open(&path, b"pass"));
    assert!(matches!(err, VaultError::Crypto(_)));
}

#[test]
fn create_twice_fails() {
    let tmp = TempDir::new();
    let path = tmp.vault_path();
    Vault::create(&path, b"pass", test_params()).unwrap();
    let err = expect_err(Vault::create(&path, b"pass", test_params()));
    assert!(matches!(err, VaultError::AlreadyExists));
}

#[test]
fn no_temp_file_left_after_save() {
    // L'écriture atomique ne doit laisser aucun fichier temporaire derrière elle.
    let tmp = TempDir::new();
    let path = tmp.vault_path();
    Vault::create(&path, b"pass", test_params()).unwrap();
    let entries: Vec<_> = fs::read_dir(&tmp.0)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "only the vault file should remain: {entries:?}"
    );
    assert_eq!(entries[0].to_string_lossy(), "vault.coffre");
}

#[test]
fn salt_and_nonce_are_fresh() {
    // Invariant : sel unique par coffre, nonce neuf à chaque écriture.
    let tmp = TempDir::new();
    let p1 = tmp.0.join("v1.coffre");
    let p2 = tmp.0.join("v2.coffre");
    let mut first = Vault::create(&p1, b"pass", test_params()).unwrap();
    let second = Vault::create(&p2, b"pass", test_params()).unwrap();

    let h1 = read_header(&p1);
    let h2 = read_header(&p2);
    assert_ne!(h1.salt, h2.salt, "salts must differ across vaults");
    assert_ne!(h1.nonce, h2.nonce, "nonces must differ");

    drop(second);
    let before = read_header(&p1);
    first.save().unwrap();
    let after = read_header(&p1);
    assert_ne!(before.nonce, after.nonce, "nonce must change on each save");
}

#[test]
fn unsupported_params_rejected_before_kdf() {
    // m_cost énorme : sans borne, Argon2 allouerait des Go de RAM avant toute
    // authentification (l'en-tête est lu avant la vérification du tag).
    let tmp = TempDir::new();
    let path = tmp.vault_path();
    let header = Header {
        version: VERSION,
        kdf_id: KDF_ARGON2ID,
        m_cost: u32::MAX,
        t_cost: 1,
        p_cost: 1,
        salt: [0u8; 32],
        nonce: [0u8; 24],
    };
    let mut bytes = header.encode().to_vec();
    bytes.extend_from_slice(&[0u8; 16]);
    fs::write(&path, &bytes).unwrap();
    let err = expect_err(Vault::open(&path, b"pass"));
    assert!(matches!(err, VaultError::UnsupportedParams));
}
