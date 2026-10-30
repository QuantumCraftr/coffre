# coffre

Un coffre de secrets local, open-source, construit sur le contre-choix : pas de course à la vitesse, mais une exigence de **vérifiabilité totale**.

[![CI](https://github.com/QuantumCraftr/coffre/actions/workflows/ci.yml/badge.svg)](https://github.com/QuantumCraftr/coffre/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#licence)
[![Status](https://img.shields.io/badge/status-pre--alpha-red.svg)](#statut)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

![coffre : coffre-fort numérique, secrets injectés en variables d'environnement, format ouvert, chiffrement moderne](assets/coffre-hero.png)

> À l'heure où l'essentiel du code est généré par IA, `coffre` fait le pari inverse : un outil du quotidien dont on peut réellement lire et auditer chaque ligne, plutôt qu'un gros binaire auquel on fait confiance sur réputation.

## Statut

**Pré-alpha.** Phases 0 et 1 terminées, Phase 2 en cours : primitives validées (Argon2id, XChaCha20-Poly1305), format v1, couche `Vault` (écriture atomique, zeroization) et CLI de base (`init`, `add`, `get`, `list`, `rm`). **Ne stockez pas encore de secrets critiques :** pas d'audit externe, property tests et fuzzing à venir. Suivi : [PLAN.md](PLAN.md).

## Pourquoi ce n'est pas un « Bitwarden killer »

Bitwarden et KeePass sont éprouvés et très bons. `coffre` n'essaie pas de faire plus de choses : il essaie d'en faire **moins**, pour qu'une personne seule puisse auditer le code de bout en bout. Trois axes :

1. **Vérifiabilité** : un périmètre minuscule, lisible en entier, sans dépendance.
2. **Format ouvert** : un fichier dont la spec tient sur une page, décryptable dans 20 ans.
3. **Pont avec les agents IA** : injecter des secrets en variables d'environnement sans jamais exposer leur valeur en clair dans une conversation.

## Principes

- **Zéro dépendance** par défaut. Toute dépendance exige une justification écrite.
- **Zéro `unsafe`** (ou confiné et justifié ligne à ligne).
- **Petit périmètre** : moins de surface, moins de failles possibles.
- **Vérification plutôt que vitesse** : test vectors officiels, property-based testing, fuzzing, revue humaine obligatoire.

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
| Dépendances | Zéro ou quasi, primitives RustCrypto pinées |
| Vérification | Test vectors officiels (RFC 9106, RFC 8439) |

Le modèle de menace complet est documenté et versionné : [THREAT_MODEL.md](THREAT_MODEL.md).
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
```

La phrase secrète est demandée sur le terminal (sans écho). Pour l'automatisation,
`COFFRE_PASSPHRASE` permet de la fournir, avec la même prudence qu'un mot de passe
passé par variable d'environnement (visible pour le même utilisateur et root).

## Commandes utiles

```bash
cargo fmt --all --check                                  # format
cargo clippy --workspace --all-targets -- -D warnings    # lint strict
cargo test --workspace                                   # tests
cargo audit                                              # vulnérabilités (RustSec)
cargo deny check                                         # supply chain (bans, licences, sources)
cargo +nightly miri test -p coffre-core                  # undefined behavior (Miri)
.venv/bin/python scripts/gen_vectors.py                  # régénérer les vecteurs de référence
```

La CI exécute ces commandes à chaque push.

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
