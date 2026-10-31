# Plan

The plan proceeds in phases, each with a strict definition of done (DoD).
A phase is not considered finished until its DoD is fully verified.
Speed is not a criterion; verification is.

## Guiding principle

We do not move on until the current phase is beyond reproach.
AI is used as an auditor (tests, fuzzers, counterexamples, review), not as a blind generator.

## Phase 0 — Foundation

Set up the verification infrastructure before any line of crypto.

- `git init`, `cargo init`, Rust workspace (`coffre-core` + `coffre-cli`).
- CI (GitHub Actions): `cargo fmt --check`, `clippy -D warnings`, `cargo test`, `cargo audit`, `cargo deny`.
- Reproducible builds: committed `Cargo.lock`, `--locked` and hermetic builds.
- Charter: no unjustified dependency, no `unsafe`.

**DoD**: green CI on an empty commit, zero clippy warnings, zero added dependency.

## Phase 1 — Cryptographic spike (done)

Validate the chosen primitives before writing any feature.

- Argon2id and XChaCha20-Poly1305 (RustCrypto) verified by **cross-validation** against independent implementations (reference C for Argon2id, libsodium for XChaCha20).
- Proofs: correct round-trip, clean failure on a wrong passphrase, detection of a modified bit, rejection of a bad AAD/nonce.
- Measures: clean `miri` (8/8 tests), zero `unsafe` in our code.

**DoD**: test vectors pass, corruption is detected, no undefined behavior. **Fulfilled.**

## Phase 2 — Format and core (done)

Implement format v1 (see THREAT_MODEL.md §5 and §8).

- Format serialization: AEAD header + payload.
- Atomic write (temporary file + rename) for crash resistance.
- Zeroization of secrets in memory.
- Core operations: `init`, `add`, `get`, `list`, `rm`.
- Property-based tests (dependency-free deterministic generator), libFuzzer fuzzing (`header_decode`, `payload_decode`), ASan and Miri.

**DoD**: property-based tests on the format, parser fuzzing, clean sanitizers. **Fulfilled.**

## Phase 3 — CLI

The `coffre` binary.

- Subcommands: `init`, `add`, `get`, `list`, `rm`.
- Golden rule: secrets never go to stdout/logs unless explicitly requested.
- Error handling without information leaks.

**DoD**: integration tests, no secret value in logs or error messages.

## Phase 4 — AI agent broker

The differentiating feature.

- `run` mode: inject the requested secrets as environment variables of a child process, without ever printing them.
- References by name (never by value), limited scope (inject-all or inject by name list).
- Minimal audit logging, without values.

**DoD**: test proving the value never appears in output, logs or an agent's context.

## Phase 5 — Hardening, audit, release

- Line-by-line review of the whole scope, by a human.
- Optional external audit of the format and crypto.
- Separate visual UI (TUI then GUI) that talks to the core without ever seeing secrets.
- crates.io release, English README and docs for the community.

**DoD**: documented full review, release, zero known security debt.

## Cross-cutting criteria

- Mandatory human review on every diff (no auto-merge).
- Every bug → regression test.
- Every security decision → THREAT_MODEL.md update in the same diff.
- Useful commands documented in README.md as we go.
