use coffre_core::crypto::{KdfParams, TAG_LEN, derive_key, open, seal};

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn argon2id_matches_reference_c() {
    let salt = hex("000102030405060708090a0b0c0d0e0f");
    let params = KdfParams {
        m_cost: 32,
        t_cost: 3,
        p_cost: 4,
    };
    let key = derive_key(b"password", &salt, &params).unwrap();
    let expected = hex("803c582b3c99a567e01b2df83cf55c4b32040cd8511aed25f051502d81ee43b2");
    assert_eq!(key.as_slice(), expected.as_slice());
}

#[test]
fn xchacha20poly1305_matches_libsodium() {
    let key: [u8; 32] = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .try_into()
        .unwrap();
    let nonce: [u8; 24] = hex("000102030405060708090a0b0c0d0e0f1011121314151617")
        .try_into()
        .unwrap();
    let ct = seal(&key, nonce, b"coffre test vector", b"header").unwrap();
    let expected = hex("fdad6919e2b7adda563752eebd37cb9c24352fc7003b83c3cd8b73435c9f2c17741a");
    assert_eq!(ct, expected);
}

#[test]
fn round_trip() {
    let key = [7u8; 32];
    let nonce = [9u8; 24];
    let plaintext = b"secret";
    let aad = b"hdr";
    let ct = seal(&key, nonce, plaintext, aad).unwrap();
    assert_eq!(ct.len(), plaintext.len() + TAG_LEN);
    let opened = open(&key, nonce, &ct, aad).unwrap();
    assert_eq!(opened, plaintext);
}

#[test]
fn detects_single_bit_corruption() {
    let key = [7u8; 32];
    let nonce = [9u8; 24];
    let aad = b"hdr";
    let mut ct = seal(&key, nonce, b"secret", aad).unwrap();
    // A single modified bit must invalidate the Poly1305 tag.
    ct[0] ^= 1;
    assert!(open(&key, nonce, &ct, aad).is_err());
}

#[test]
fn rejects_wrong_aad() {
    let key = [7u8; 32];
    let nonce = [9u8; 24];
    let ct = seal(&key, nonce, b"secret", b"hdr").unwrap();
    assert!(open(&key, nonce, &ct, b"other").is_err());
}

#[test]
fn rejects_wrong_nonce() {
    let key = [7u8; 32];
    let nonce = [9u8; 24];
    let ct = seal(&key, nonce, b"secret", b"hdr").unwrap();
    let mut bad_nonce = nonce;
    bad_nonce[0] ^= 1;
    assert!(open(&key, bad_nonce, &ct, b"hdr").is_err());
}

#[test]
fn wrong_password_fails_to_decrypt() {
    let salt = [1u8; 32];
    let params = KdfParams {
        m_cost: 32,
        t_cost: 3,
        p_cost: 4,
    };
    let key = derive_key(b"correct", &salt, &params).unwrap();
    let wrong = derive_key(b"wrong", &salt, &params).unwrap();
    let nonce = [0u8; 24];
    let ct = seal(&key, nonce, b"secret", b"").unwrap();
    assert!(open(&wrong, nonce, &ct, b"").is_err());
}

#[test]
fn empty_plaintext_round_trip() {
    let key = [0u8; 32];
    let nonce = [0u8; 24];
    let ct = seal(&key, nonce, b"", b"").unwrap();
    assert_eq!(ct.len(), TAG_LEN);
    let opened = open(&key, nonce, &ct, b"").unwrap();
    assert!(opened.is_empty());
}
