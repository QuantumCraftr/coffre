## Summary

<!-- What does this PR change, and why? -->

## Testing

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo audit`
- [ ] `cargo deny check`
- [ ] If parser/crypto: Miri, fuzz and ASan were run

## Checklist

- [ ] No new dependency without an entry in `DEPENDENCIES.md`
- [ ] No `unsafe` (or justified line by line)
- [ ] Security decisions update `THREAT_MODEL.md` in this PR
- [ ] I read and understood every line of AI-generated code in this diff
