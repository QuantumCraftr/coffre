# Contribuer

Merci. Ce projet privilégie la **vérifiabilité** à la vitesse.

## Avant d'ouvrir une PR

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
cargo deny check
```

Pour tout changement touchant le parseur ou la crypto :

```bash
cargo +nightly miri test -p coffre-core --test format --test properties
cargo +nightly fuzz run payload_decode -- -runs=100000
RUSTFLAGS="-Zsanitizer=address" cargo test -p coffre-core --tests
```

## Règles

- Zéro dépendance par défaut ; toute dépendance doit être justifiée dans `DEPENDENCIES.md`.
- Zéro `unsafe` (ou confiné et justifié ligne à ligne).
- Chaque bug corrigé devient un test de régression.
- Toute décision de sécurité met à jour `THREAT_MODEL.md` dans le même diff.
- Les diffs générés par IA doivent être **lus et compris** ligne par ligne avant d'être soumis.

## Sécurité

Ne pas ouvrir d'issue publique pour une faille : voir [`SECURITY.md`](SECURITY.md).

## Commits

Messages concis, en anglais, au format conventionnel (`feat:`, `fix:`, `docs:`, `test:`, `ci:`).
