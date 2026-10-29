# Plan

Le plan avance par phases, chacune avec une définition de done (DoD) stricte.
Aucune phase n'est considérée finie tant que sa DoD n'est pas entièrement vérifiée.
La vitesse n'est pas un critère ; la vérification en est un.

## Principe directeur

On n'avance pas tant que la phase en cours n'est pas irréprochable.
L'IA est utilisée comme auditeur (tests, fuzzers, contre-exemples, revue), pas comme générateur aveugle.

## Phase 0 — Socle

Mise en place de l'infrastructure de vérification avant toute ligne de crypto.

- `git init`, `cargo init`, workspace Rust (`coffre-core` + `coffre-cli`).
- CI (GitHub Actions) : `cargo fmt --check`, `clippy -D warnings`, `cargo test`, `cargo audit`, `cargo deny`.
- Builds reproductibles : `Cargo.lock` committé, builds en `--locked` et hermétiques.
- Charte : interdiction de dépendance non justifiée, interdiction d'`unsafe`.

**DoD** : CI verte sur un commit vide, zéro warning clippy, zéro dépendance ajoutée.

## Phase 1 — Spike cryptographique (terminée)

Valider les primitives choisies avant d'écrire la moindre fonctionnalité.

- Argon2id et XChaCha20-Poly1305 (RustCrypto) vérifiés par **validation croisée** contre des implémentations indépendantes (référence C pour Argon2id, libsodium pour XChaCha20).
- Preuves : round-trip correct, échec propre sur mauvais mot de passe, détection d'un bit modifié, rejet d'un mauvais AAD/nonce.
- Mesures : `miri` propre (8/8 tests), zéro `unsafe` dans notre code.

**DoD** : les vecteurs de test passent, la corruption est détectée, pas d'undefined behavior. **Remplie.**

## Phase 2 — Format et cœur

Implémenter le format v1 (voir THREAT_MODEL.md §5 et §8).

- Sérialisation du format : en-tête + payload AEAD.
- Écriture atomique (fichier temporaire + rename) pour la résistance aux crashs.
- Zeroization des secrets en mémoire.
- Opérations cœur : `init`, `add`, `get`, `list`, `rm`.

**DoD** : property-based tests sur le format, fuzzing du parser, sanitizers propres.

## Phase 3 — CLI

Le binaire `coffre`.

- Sous-commandes : `init`, `add`, `get`, `list`, `rm`.
- Règle d'or : les secrets ne sortent jamais sur stdout/logs sauf demande explicite.
- Gestion d'erreur sans fuite d'information.

**DoD** : tests d'intégration, aucune valeur de secret dans les logs ni les messages d'erreur.

## Phase 4 — Courtier pour agents IA

La fonctionnalité différenciante.

- Mode `run` : injecte les secrets demandés en variables d'environnement d'un process enfant, sans jamais les afficher.
- Références par nom (jamais par valeur), portée limitée (inject-all ou inject par liste de noms).
- Journalisation d'audit minimale, sans valeurs.

**DoD** : test prouvant que la valeur n'apparaît jamais dans la sortie, les logs ni le contexte d'un agent.

## Phase 5 — Durcissement, audit, publication

- Revue ligne à ligne de tout le périmètre, par un humain.
- Audit externe optionnel du format et de la crypto.
- UI visuelle séparée (TUI puis GUI) qui parle au cœur sans jamais voir les secrets.
- Publication crates.io, README et docs en anglais pour la communauté.

**DoD** : revue complète documentée, publication, zéro dette de sécurité connue.

## Critères transverses

- Revue humaine obligatoire sur chaque diff (pas de merge auto).
- Chaque bug → test de régression.
- Chaque décision de sécurité → mise à jour de THREAT_MODEL.md dans le même diff.
- Commandes utiles documentées dans README.md au fil de l'eau.
