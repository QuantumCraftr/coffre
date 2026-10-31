use coffre_core::format::{
    Entries, FormatError, HEADER_LEN, Header, KDF_ARGON2ID, VERSION, decode_payload, encode_payload,
};

fn sample_header() -> Header {
    Header {
        version: VERSION,
        kdf_id: KDF_ARGON2ID,
        m_cost: 65536,
        t_cost: 3,
        p_cost: 1,
        salt: [0x11; 32],
        nonce: [0x22; 24],
    }
}

#[test]
fn header_len_is_79() {
    assert_eq!(HEADER_LEN, 79);
}

#[test]
fn header_round_trip() {
    let header = sample_header();
    let bytes = header.encode();
    assert_eq!(bytes.len(), HEADER_LEN);
    assert_eq!(Header::decode(&bytes).unwrap(), header);
}

#[test]
fn header_rejects_short() {
    assert_eq!(
        Header::decode(&[0u8; HEADER_LEN - 1]),
        Err(FormatError::TooShort)
    );
}

#[test]
fn header_rejects_bad_magic() {
    let mut bytes = sample_header().encode();
    bytes[0] = b'X';
    assert_eq!(Header::decode(&bytes), Err(FormatError::BadMagic));
}

#[test]
fn header_rejects_bad_version() {
    let mut bytes = sample_header().encode();
    bytes[8..10].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(
        Header::decode(&bytes),
        Err(FormatError::UnsupportedVersion(2))
    );
}

#[test]
fn header_rejects_bad_kdf() {
    let mut bytes = sample_header().encode();
    bytes[10] = 9;
    assert_eq!(Header::decode(&bytes), Err(FormatError::UnsupportedKdf(9)));
}

#[test]
fn payload_round_trip_empty() {
    let entries = Entries::new();
    let bytes = encode_payload(&entries).unwrap();
    assert_eq!(decode_payload(&bytes).unwrap(), entries);
}

#[test]
fn payload_round_trip_with_entries() {
    let mut entries = Entries::new();
    entries.insert("database_url".to_string(), b"postgres://x".to_vec());
    entries.insert("token".to_string(), vec![0, 1, 2, 0xff]);
    let bytes = encode_payload(&entries).unwrap();
    assert_eq!(decode_payload(&bytes).unwrap(), entries);
}

#[test]
fn payload_round_trip_empty_value() {
    let mut entries = Entries::new();
    entries.insert("k".to_string(), Vec::new());
    let bytes = encode_payload(&entries).unwrap();
    assert_eq!(decode_payload(&bytes).unwrap(), entries);
}

#[test]
fn payload_rejects_truncated_len() {
    assert_eq!(decode_payload(&[0, 0]), Err(FormatError::TooShort));
}

#[test]
fn payload_rejects_truncated_body() {
    // Announces a 5-byte name but provides none of it.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&5u32.to_be_bytes());
    assert_eq!(decode_payload(&bytes), Err(FormatError::TooShort));
}

#[test]
fn payload_rejects_trailing_data() {
    let mut bytes = encode_payload(&Entries::new()).unwrap();
    bytes.push(0xab);
    assert_eq!(decode_payload(&bytes), Err(FormatError::TrailingData));
}

#[test]
fn payload_rejects_invalid_utf8() {
    // Hand-crafted name: 0xff is not valid UTF-8.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.push(0xff);
    bytes.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(decode_payload(&bytes), Err(FormatError::InvalidUtf8));
}

#[test]
fn payload_rejects_duplicate_name() {
    // Two "k" entries: ambiguity is rejected rather than silently overwritten.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&2u32.to_be_bytes());
    for _ in 0..2 {
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'k');
        bytes.extend_from_slice(&0u32.to_be_bytes());
    }
    assert_eq!(decode_payload(&bytes), Err(FormatError::DuplicateName));
}
