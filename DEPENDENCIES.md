# Dépendances

Règle : **zéro dépendance par défaut**. Toute dépendance ajoutée doit être justifiée ici,
pinée dans `Cargo.lock` (committé), et validée par revue humaine.

## Dépendances directes (coffre-core)

| Crate | Version | Rôle | Justification |
| --- | --- | --- | --- |
| `argon2` | 0.6 | Dérivation de clé (Argon2id) | Standard OWASP pour les mots de passe. On ne réinvente pas la crypto. Features minimales (`alloc`), `getrandom`/`password-hash` désactivés. |
| `chacha20poly1305` | 0.11 | AEAD XChaCha20-Poly1305 | Constant-time en pur logiciel, nonce 192 bits. Features minimales (`alloc`), `getrandom` désactivé. |

Les deux sont des primitives **RustCrypto**, pur Rust, sans `unsafe` dans notre code.
Leur correction est vérifiée par **validation croisée** contre des implémentations
indépendantes (voir `coffre-core/tests/crypto_vectors.rs`) :

- Argon2id : sortie identique à l'implémentation C de référence (via `argon2-cffi`).
- XChaCha20-Poly1305 : sortie identique à libsodium (via PyNaCl).

## Dépendances transitives

Listées et pinées dans `Cargo.lock`. Ce sont les sous-composants des primitives
RustCrypto (blake2, chacha20, poly1305, aead, etc.). Vérifiées par `cargo audit`
(RustSec) et `cargo deny` (bans, licences, sources) à chaque build.

## Outils de développement (non liés au binaire)

- `scripts/gen_vectors.py` : génère les vecteurs de référence. Utilise un venv Python
  isolé (`argon2-cffi`, `pynacl`). Aucun impact sur le binaire Rust.
