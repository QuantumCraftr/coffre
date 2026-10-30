use coffre_core::format::{Entries, Header, KDF_ARGON2ID, VERSION, decode_payload, encode_payload};

// Générateur déterministe (xorshift64*) : des milliers d'entrées reproductibles,
// sans dépendance de test. Ce n'est pas de la crypto, seulement de la génération.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }

    fn vec(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.below(max_len + 1);
        (0..len).map(|_| self.byte()).collect()
    }

    fn name(&mut self) -> String {
        let len = self.below(12);
        (0..len)
            .map(|_| char::from(b'a' + (self.byte() % 26)))
            .collect()
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for slot in &mut out {
            *slot = self.byte();
        }
        out
    }
}

#[test]
fn header_decode_never_panics_on_arbitrary_bytes() {
    let mut rng = Rng::new(0xC0FF_EE01);
    for _ in 0..5000 {
        let bytes = rng.vec(200);
        let _ = Header::decode(&bytes);
    }
}

#[test]
fn payload_decode_never_panics_on_arbitrary_bytes() {
    let mut rng = Rng::new(0xBADF_00D1);
    for _ in 0..5000 {
        let bytes = rng.vec(256);
        let _ = decode_payload(&bytes);
    }
}

#[test]
fn header_round_trips_random_values() {
    let mut rng = Rng::new(0x1234_5678);
    for _ in 0..2000 {
        let header = Header {
            version: VERSION,
            kdf_id: KDF_ARGON2ID,
            m_cost: rng.next_u64() as u32,
            t_cost: rng.next_u64() as u32,
            p_cost: rng.next_u64() as u32,
            salt: rng.array(),
            nonce: rng.array(),
        };
        let encoded = header.encode();
        assert_eq!(Header::decode(&encoded).unwrap(), header);
    }
}

#[test]
fn payload_round_trips_random_entries() {
    let mut rng = Rng::new(0xDEAD_BEEF);
    for _ in 0..3000 {
        let mut entries = Entries::new();
        for _ in 0..rng.below(8) {
            entries.insert(rng.name(), rng.vec(64));
        }
        let encoded = encode_payload(&entries).unwrap();
        assert_eq!(decode_payload(&encoded).unwrap(), entries);
    }
}

#[test]
fn truncated_payload_never_panics() {
    let mut rng = Rng::new(0xFEED_FACE);
    for _ in 0..200 {
        let mut entries = Entries::new();
        for _ in 0..rng.below(5) {
            entries.insert(rng.name(), rng.vec(32));
        }
        let encoded = encode_payload(&entries).unwrap();
        for len in 0..=encoded.len() {
            let _ = decode_payload(&encoded[..len]);
        }
    }
}

#[test]
fn flipped_header_byte_never_panics() {
    let mut rng = Rng::new(0x0DDB_A111);
    for _ in 0..200 {
        let header = Header {
            version: VERSION,
            kdf_id: KDF_ARGON2ID,
            m_cost: 65536,
            t_cost: 3,
            p_cost: 1,
            salt: rng.array(),
            nonce: rng.array(),
        };
        let mut encoded = header.encode();
        for i in 0..encoded.len() {
            encoded[i] ^= 1;
            let _ = Header::decode(&encoded);
            encoded[i] ^= 1;
        }
    }
}
