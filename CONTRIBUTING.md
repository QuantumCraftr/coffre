# Contributing

Thank you. This project values **verifiability** over speed.

## Before opening a PR

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
cargo deny check
```

For any change touching the parser or crypto:

```bash
cargo +nightly miri test -p coffre-core --test format --test properties
cargo +nightly fuzz run payload_decode -- -runs=100000
RUSTFLAGS="-Zsanitizer=address" cargo test -p coffre-core --tests
```

## Rules

- Minimal dependencies: none added by default; any dependency must be justified in `DEPENDENCIES.md`.
- Zero `unsafe` (or confined and justified line by line).
- Every fixed bug becomes a regression test.
- Any security decision updates `THREAT_MODEL.md` in the same diff.
- AI-generated diffs must be **read and understood** line by line before being submitted.

## Security

Do not open a public issue for a vulnerability: see [`SECURITY.md`](SECURITY.md).

## Commits

Concise messages, in English, in conventional format (`feat:`, `fix:`, `docs:`, `test:`, `ci:`).
