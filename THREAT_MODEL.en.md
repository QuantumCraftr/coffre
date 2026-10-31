<p align="center"><a href="THREAT_MODEL.md">Français</a> | <strong>English</strong></p>

# Threat model

This document fixes the threat model and cryptographic choices for version 1.
It is versioned with the code: any security change must go through it first.

## 1. Scope

`coffre` stores secrets (passwords, keys, environment variables) in a single, end-to-end
encrypted, local file. Version 1 has no network, no server and no complex binary format.

In scope:

- the encrypted file format;
- key derivation and encryption;
- the local CLI and the agent "broker" mode (injection via env vars);
- resistance to corruption and crashes.

Out of scope (v1):

- multi-machine sync, server/VPS, sharing between users;
- graphical interface;
- any asymmetric key exchange.

## 2. Trust assumptions

We trust:

- the hardware (CPU, RAM, bus) is not compromised;
- the OS and terminal are not compromised **at the time of use**;
- the master passphrase is strong and not reused elsewhere;
- the OS random generator (CSPRNG) is sound.

Everything else is treated as untrusted, including the vault file itself.

## 3. Attacker model

| Profile | Capabilities | Covered? |
| --- | --- | --- |
| Remote attacker, no access | reads network traffic (v1: none) | Not applicable |
| Local unprivileged attacker | reads/copies the vault file | Yes |
| Local privileged attacker (root) | reads RAM, hooks the app, keylogs | No (see §6) |
| Future storage/VPS attacker | reads encrypted blobs | Yes, by construction |
| Supply-chain attacker | compromises a dependency | Yes, through scope reduction |
| Physical attacker | cold boot, evil maid, DMA | No (see §6) |
| Quantum attacker | realistic quantum computing capability | Partial (see §5) |

## 4. Security properties

- **Confidentiality**: without the passphrase, the content is unreadable.
- **Integrity**: any change to the file (even 1 bit) is detected and decryption is refused.
- **Authenticity**: only whoever knows the passphrase can produce a valid file.
- **Anti-oracle**: nothing in the file lets one test a password faster than a full decryption.
- **No memory leak**: secrets are wiped (zeroization) after use, as far as Rust allows.

## 5. Frozen cryptographic choices (v1)

| Element | Choice | Rationale |
| --- | --- | --- |
| Key derivation (KDF) | Argon2id, m=64 MiB (65536 KiB), t=3, p=1 | OWASP 2026, resists GPU/ASIC and side channels |
| Salt | 32 bytes, OS CSPRNG | Unique per vault, anti-rainbow |
| Encryption | XChaCha20-Poly1305 | Constant-time in pure software, 192-bit nonce (anti-reuse) |
| Key | 256 bits, KDF output | Symmetric, resists Grover (~128 effective bits) |
| Integrity | Poly1305 tag (16 bytes), AAD = full header | The AEAD authenticates envelope and content together |
| Password verification | No cleartext "key check value" | Avoids an oracle; only the AEAD tag decides |
| Random generator | OS CSPRNG (getrandom) | Never a homemade PRNG |

Reserves (unused in v1, to enable if needed):

- external integrity or hashing: SHA-256 (or BLAKE3, or SHA-3);
- post-quantum asymmetric: ML-KEM-768 (FIPS 203) + ML-DSA (FIPS 204) in hybrid mode;
- artifact signatures: Sigstore/cosign.

### Quantum note

The core is symmetric: Argon2id (hash-based KDF) and ChaCha20 (256 bits). Grover's algorithm
only halves security (~128 effective bits), which remains out of reach. Quantum fragility
(Shor) only affects asymmetric cryptography, absent from v1. If we add it, we will move to
hybrid post-quantum.

## 6. Covered threats and countermeasures

| Threat | Countermeasure |
| --- | --- |
| Passphrase brute force | High-cost Argon2id (~250 ms per attempt) |
| Direct file read | AEAD: unreadable without the key |
| File modification/corruption | Poly1305 tag: any alteration is refused |
| Nonce reuse | Random 192-bit nonce (XChaCha20) |
| Secret memory leak | Explicit zeroization, confined-access structures |
| Supply chain (typosquat, slop squat, XZ-style backdoor) | Minimal, justified dependencies, strict pinning, reproducible builds, human review |
| Verification oracle | No cleartext check value in the header |
| Crash during write | Atomic write (temporary file + rename) |
| Software side channels (timing/cache) | Constant-time ChaCha20; Argon2id resistant by design |

## 7. Explicitly out-of-scope threats

These threats are NOT covered, and we state it in writing:

- **root attacker on the machine during use** (can hook the process, read RAM, keylog);
- **hardware or software keylogger** already installed;
- **cold boot / DMA** (reading residual RAM);
- **evil maid** (altering hardware or software between two uses);
- **physical denial of service** or destruction of the file without a backup.

No software vault can defend against an attacker who already controls the machine. Our promise
is this: if the machine is healthy at the time of use, the file can sit anywhere without
anything leaking.

## 8. Engineering rules (the harness)

- **Minimal dependencies**: none added by default; every dependency requires a written
  justification and an audit.
- **Zero `unsafe`** (or confined and justified line by line).
- Primitives validated by **cross-validation**: XChaCha20-Poly1305 identical to libsodium,
  Argon2id identical to the reference C implementation (argon2-cffi).
- **Property-based testing** (dependency-free deterministic generator), **fuzzing**
  (cargo-fuzz), **Miri**, **ASan** in CI.
- **Reproducible builds**: committed lockfile, hermetic builds.
- **Mandatory human review**: no AI diff is merged without line-by-line reading.
- Every fixed bug becomes a permanent **regression test**.
- Any change to this document follows the same review process as code.

## 9. Known limitations

- **Concurrency**: no file lock. Two simultaneous writes end in "last one wins".
- **Symlinks**: `rename` replaces the destination entry; a vault reached through a symbolic
  link sees the link replaced, not the target.
- **Windows**: no directory `fsync`, no `0600` permissions, and non-UTF-8 binary secrets are
  lossily converted for injection via `run`.
- **Zeroization**: best effort. Transient copies of the key may exist on the stack
  (`Key::from`, `derive_key` return); the internal `stdin` buffer (`add` read) is not wiped;
  the OS may copy pages (swap, core dump).
- **Filesystems**: `init` writes the final file directly (`create_new`), without rename; a
  crash during `init` may leave a truncated vault, to be recreated. Subsequent writes are
  atomic.
- **`run`**: the child process environment remains readable by the same user and root. The
  CLI removes `COFFRE_PASSPHRASE` from the child's environment. On Unix, `coffre` is replaced
  by the child (`exec`): no parent process keeps the passphrase or secrets in memory. On
  Windows, the parent waits for the child and keeps its own environment.
- **`get`**: the value is followed by a newline.
