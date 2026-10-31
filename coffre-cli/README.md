# coffre-cli

Interface en ligne de commande du coffre de secrets `coffre` :

- `init`, `add`, `get`, `list`, `rm` pour gérer les secrets ;
- `run` pour injecter des secrets en variables d'environnement d'un process enfant,
  sans jamais les afficher (mode courtier pour agents).

Projet complet, threat model et format : https://github.com/QuantumCraftr/coffre

Installation (une fois publié) : `cargo install coffre-cli`, qui fournit le binaire `coffre`.

Licence : MIT OR Apache-2.0.
