"""Generate cross-validation test vectors for coffre.

Uses two independent reference implementations:
  - argon2-cffi (reference C implementation) for Argon2id.
  - PyNaCl / libsodium for XChaCha20-Poly1305.

Run: .venv/bin/python scripts/gen_vectors.py
The Rust tests assert that RustCrypto produces the exact same outputs.
"""

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt


def argon2id_vector():
    password = b"password"
    salt = bytes(range(16))
    out = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=3,
        memory_cost=32,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )
    print("=== Argon2id (reference C) ===")
    print(f"password = {password!r}")
    print(f"salt     = {salt.hex()}")
    print("params   = m=32 KiB, t=3, p=4, hashlen=32")
    print(f"key      = {out.hex()}")
    print()


def xchacha20_vector():
    key = bytes(range(32))
    nonce = bytes(range(24))
    plaintext = b"coffre test vector"
    aad = b"header"
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    print("=== XChaCha20-Poly1305 (libsodium) ===")
    print(f"key        = {key.hex()}")
    print(f"nonce      = {nonce.hex()}")
    print(f"plaintext  = {plaintext!r}")
    print(f"aad        = {aad!r}")
    print(f"ciphertext = {ct.hex()}")
    print()


if __name__ == "__main__":
    argon2id_vector()
    xchacha20_vector()
