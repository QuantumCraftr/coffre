# Dependencies

Rule: **minimal dependencies by default**. Any added dependency must be justified here, pinned
in `Cargo.lock` (committed), and validated by human review.

## Direct dependencies (coffre-core)

| Crate | Version | Role | Justification |
| --- | --- | --- | --- |
| `argon2` | 0.6 | Key derivation (Argon2id) | OWASP standard. Features `alloc` + `zeroize` (key material wiped on drop), `getrandom`/`password-hash` disabled. |
| `chacha20poly1305` | 0.11 | XChaCha20-Poly1305 AEAD | Constant-time in pure software, 192-bit nonce. Features `alloc` + `zeroize`, `getrandom` disabled. |
| `getrandom` | 0.4 | OS CSPRNG | Salt unique per vault, fresh nonce on every write, temporary file suffix. Features `std` + `sys_rng`. |
| `zeroize` | 1.9 | Memory wiping | Zeroization of the derived key, decrypted payload and secret names/values on drop. |

The `argon2` and `chacha20poly1305` primitives are **RustCrypto**, pure Rust, with no `unsafe`
in our code. Their correctness is verified by **cross-validation** against independent
implementations (see `coffre-core/tests/crypto_vectors.rs`):

- Argon2id: output identical to the reference C implementation (via `argon2-cffi`).
- XChaCha20-Poly1305: output identical to libsodium (via PyNaCl).

## `coffre-cli` dependencies

| Crate | Version | Role | Justification |
| --- | --- | --- | --- |
| `rpassword` | 7.5 | Echo-free passphrase input | Avoids displaying the password. Wraps termios calls, so no `unsafe` in our code. Depends on `rtoolbox` (small). |
| `zeroize` | 1.9 | Wiping of the entered passphrase and value | Same reasons as the core. |

## Fuzzing (not shipped)

The `fuzz/` crate is excluded from the workspace and never shipped. It depends on
`libfuzzer-sys` (dev only) for the `header_decode` and `payload_decode` targets. No impact on
the binary.

## Transitive dependencies

Listed and pinned in `Cargo.lock`. Sub-components of the RustCrypto primitives, plus the
`getrandom` dependencies (`r-efi`, `rand_core` for platform backends). Checked by `cargo audit`
(RustSec) and `cargo deny` (bans, licenses, sources) on every build.

## Development tools (not linked to the binary)

- `scripts/gen_vectors.py`: generates the reference vectors. Uses an isolated Python venv
  (`argon2-cffi`, `pynacl`). No impact on the Rust binary.
- `scripts/verify_vault.py`: independent reader (`argon2-cffi` + PyNaCl) that opens a vault
  according to `FORMAT.md`, to verify the Rust implementation without reading Rust.
