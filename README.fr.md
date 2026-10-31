<p align="center"><strong>Français</strong> | <a href="README.md">English</a></p>

<h1 align="center">coffre</h1>

<p align="center">
  <strong>Un coffre de secrets local, open-source, construit sur le contre-choix :<br>
  pas de course à la vitesse, mais une exigence de <em>vérifiabilité totale</em>.</strong>
</p>

<p align="center">
  <a href="https://github.com/QuantumCraftr/coffre/actions/workflows/ci.yml"><img src="https://github.com/QuantumCraftr/coffre/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="#licence"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="License"></a>
  <a href="#statut"><img src="https://img.shields.io/badge/status-pre--alpha-red.svg" alt="Status"></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-stable-orange.svg" alt="Rust"></a>
</p>

<p align="center">
  <img width="820" alt="coffre : coffre-fort numérique, secrets injectés en variables d'environnement, format ouvert, chiffrement moderne" src="assets/coffre-hero.png">
</p>

> À l'heure où l'essentiel du code est généré par IA, `coffre` fait le pari inverse : un outil du quotidien dont on peut réellement lire et auditer chaque ligne, plutôt qu'un gros binaire auquel on fait confiance sur réputation.

## Statut

**Pré-alpha.** Phases 0, 1 et 2 terminées : primitives validées (Argon2id, XChaCha20-Poly1305), format v1, couche `Vault` (écriture atomique, zeroization), CLI (`init`, `add`, `get`, `list`, `rm`, `run`), tests à propriétés, fuzzing libFuzzer, ASan et Miri. Pas encore d'audit externe : **ne stockez pas encore de secrets critiques.** Voir [SECURITY.md](SECURITY.md) et [PLAN.md](PLAN.md).

## Pourquoi ce n'est pas un « Bitwarden killer »

Bitwarden et KeePass sont éprouvés et très bons. `coffre` n'essaie pas de faire plus de choses : il essaie d'en faire **moins**, pour qu'une personne seule puisse auditer le code de bout en bout. Trois axes :

1. **Vérifiabilité** : un périmètre minuscule, lisible en entier, avec un minimum de dépendances, toutes justifiées.
2. **Format ouvert** : un fichier dont la spec tient sur une page, décryptable dans 20 ans.
3. **Pont avec les agents IA** : injecter des secrets en variables d'environnement sans jamais exposer leur valeur en clair dans une conversation.

## Principes

- **Dépendances minimales** : aucune ajoutée par défaut ; toute dépendance exige une justification écrite.
- **Zéro `unsafe`** (ou confiné et justifié ligne à ligne).
- **Petit périmètre** : moins de surface, moins de failles possibles.
- **Vérification plutôt que vitesse** : validation croisée, property-based testing, fuzzing, revue humaine obligatoire.

## Fonctionnalités cibles (v1)

- `init` : créer un coffre chiffré.
- `add` / `get` / `list` / `rm` : gérer des secrets.
- `run` : lancer une commande avec les secrets injectés en variables d'environnement, sans les afficher (mode « courtier » pour agents IA).

## Choix techniques

| Sujet | Décision |
| --- | --- |
| Langage | Rust (édition 2024) |
| Dérivation de clé | Argon2id (m=64 MiB, t=3, p=1) |
| Chiffrement | XChaCha20-Poly1305 (clé 256 bits, nonce 192 bits) |
| Intégrité | Tag Poly1305 de l'AEAD, bindé sur l'en-tête |
| Dépendances | Minimales et justifiées (5 directes), primitives RustCrypto pinées |
| Vérification | Validation croisée (libsodium, implémentation C d'Argon2) |

Le modèle de menace complet est documenté et versionné : [THREAT_MODEL.fr.md](THREAT_MODEL.fr.md).
Chaque dépendance est justifiée : [DEPENDENCIES.md](DEPENDENCIES.md).

## Mise en route

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # Rust (si absent)
rustup component add rustfmt clippy                               # composants
cargo install cargo-audit cargo-deny                             # outils de contrôle
cargo build
```

## Utilisation

```bash
coffre init ~/.coffre/vault                 # crée le coffre (phrase secrète demandée)
coffre add  ~/.coffre/vault github_token     # valeur lue sur stdin ou demandée
coffre get  ~/.coffre/vault github_token     # affiche la valeur
coffre list ~/.coffre/vault                  # liste les noms
coffre rm   ~/.coffre/vault github_token     # supprime
coffre run  ~/.coffre/vault GITHUB_TOKEN -- ./deploy.sh   # injecte GITHUB_TOKEN en env var
```

La phrase secrète est demandée sur le terminal (sans écho). Pour l'automatisation,
`COFFRE_PASSPHRASE` permet de la fournir, avec la même prudence qu'un mot de passe
passé par variable d'environnement (visible pour le même utilisateur et root).

`run` injecte les secrets demandés dans l'environnement du process enfant, sans jamais les
afficher côté `coffre`. Limite assumée : l'environnement d'un process est lisible par le même
utilisateur et root (`/proc/<pid>/environ`). À réserver aux agents et scripts.

`get` écrit la valeur suivie d'un saut de ligne ; tiens-en compte pour les secrets binaires.

## Commandes utiles

```bash
cargo fmt --all --check                                  # format
cargo clippy --workspace --all-targets -- -D warnings    # lint strict
cargo test --workspace                                   # tests
cargo audit                                              # vulnérabilités (RustSec)
cargo deny check                                         # supply chain (bans, licences, sources)
cargo +nightly miri test -p coffre-core                  # undefined behavior (Miri)
RUSTFLAGS="-Zsanitizer=address" cargo test -p coffre-core --tests   # AddressSanitizer
cargo +nightly fuzz run payload_decode -- -runs=100000    # fuzzing (libFuzzer)
.venv/bin/python scripts/gen_vectors.py                  # régénérer les vecteurs de référence
```

La CI exécute ces commandes à chaque push.

## Vérification indépendante

Le format est documenté dans [FORMAT.fr.md](FORMAT.fr.md). Un lecteur Python séparé, écrit
d'après cette spec et utilisant argon2-cffi et PyNaCl (libsodium), peut déchiffrer un coffre
produit par `coffre` :

```bash
COFFRE_PASSPHRASE=... .venv/bin/python scripts/verify_vault.py ~/.coffre/vault
```

Cela vérifie que l'implémentation Rust correspond au format et à la crypto documentés, sans
lire de Rust.

## Structure

```
coffre/
  Cargo.toml                 # workspace
  deny.toml                  # cargo-deny (advisories, bans, licences, sources)
  .github/workflows/ci.yml   # CI : fmt, clippy, test, audit, deny
  coffre-core/               # bibliothèque : format, crypto, zeroization
  coffre-cli/                # binaire : init, add, get, list, run
```

## Licence

Double licence au choix : [MIT](LICENSE-MIT) ou [Apache-2.0](LICENSE-APACHE).
