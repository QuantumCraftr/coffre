# Dépendances

Règle : **zéro dépendance par défaut**. Toute dépendance ajoutée doit être justifiée ici,
pinée dans `Cargo.lock` (committé), et validée par revue humaine.

## Dépendances directes (coffre-core)

| Crate | Version | Rôle | Justification |
| --- | --- | --- | --- |
| `argon2` | 0.6 | Dérivation de clé (Argon2id) | Standard OWASP. Features `alloc` + `zeroize` (matériel de clé effacé à la destruction), `getrandom`/`password-hash` désactivés. |
| `chacha20poly1305` | 0.11 | AEAD XChaCha20-Poly1305 | Constant-time en pur logiciel, nonce 192 bits. Features `alloc` + `zeroize`, `getrandom` désactivé. |
| `getrandom` | 0.4 | CSPRNG de l'OS | Sel unique par coffre, nonce neuf à chaque écriture, suffixe des fichiers temporaires. Features `std` + `sys_rng`. |
| `zeroize` | 1.9 | Effacement mémoire | Zeroization de la clé dérivée, du payload déchiffré et des noms/valeurs de secrets à la destruction. |

Les primitives `argon2` et `chacha20poly1305` sont **RustCrypto**, pur Rust, sans `unsafe`
dans notre code. Leur correction est vérifiée par **validation croisée** contre des
implémentations indépendantes (voir `coffre-core/tests/crypto_vectors.rs`) :

- Argon2id : sortie identique à l'implémentation C de référence (via `argon2-cffi`).
- XChaCha20-Poly1305 : sortie identique à libsodium (via PyNaCl).

## Dépendances de `coffre-cli`

| Crate | Version | Rôle | Justification |
| --- | --- | --- | --- |
| `rpassword` | 7.5 | Saisie de la phrase secrète sans écho | Évite l'affichage du mot de passe. Encapsule les appels termios, donc pas de `unsafe` dans notre code. Dépend de `rtoolbox` (petit). |
| `zeroize` | 1.9 | Effacement de la phrase et de la valeur saisies | Mêmes raisons que côté cœur. |

## Dépendances transitives

Listées et pinées dans `Cargo.lock`. Sous-composants des primitives RustCrypto, plus les
dépendances de `getrandom` (`r-efi`, `rand_core` pour les backends plateforme). Vérifiées
par `cargo audit` (RustSec) et `cargo deny` (bans, licences, sources) à chaque build.

## Outils de développement (non liés au binaire)

- `scripts/gen_vectors.py` : génère les vecteurs de référence. Utilise un venv Python
  isolé (`argon2-cffi`, `pynacl`). Aucun impact sur le binaire Rust.
