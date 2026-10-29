# Threat model

Ce document fige le modèle de menace et les choix cryptographiques de la version 1.
Il est versionné avec le code : toute évolution de la sécurité doit d'abord passer par ici.

## 1. Objet et périmètre

`coffre` stocke des secrets (mots de passe, clés, variables d'environnement) dans un fichier
unique, chiffré de bout en bout, local. La version 1 n'a ni réseau, ni serveur, ni format binaire complexe.

Dans le périmètre :

- le format de fichier chiffré ;
- la dérivation de clé et le chiffrement ;
- la CLI locale et le mode "courtier" pour agents (injection en env vars) ;
- la résistance à la corruption et aux crashs.

Hors périmètre (v1) :

- synchronisation multi-machines, serveur/VPS, partage entre utilisateurs ;
- interface graphique ;
- tout échange de clé asymétrique.

## 2. Hypothèses de confiance

On fait confiance à :

- le matériel (CPU, RAM, bus) n'est pas compromis ;
- l'OS et le terminal ne sont pas compromis **au moment de l'usage** ;
- la passphrase maîtresse est forte et non réutilisée ailleurs ;
- le générateur aléatoire de l'OS (CSPRNG) est sain.

Tout le reste est traité comme non fiable, y compris le fichier de coffre lui-même.

## 3. Modèle d'attaquant

| Profil | Capacités | Couvert ? |
| --- | --- | --- |
| Attaquant distant, sans accès | lit du trafic réseau (v1 : aucun) | Non applicable |
| Attaquant local, non privilégié | lit/copie le fichier de coffre | Oui |
| Attaquant local, privilégié (root) | lit la RAM, hook l'app, keylog | Non (voir §6) |
| Attaquant du stockage/VPS futur | lit les blobs chiffrés | Oui, par construction |
| Attaquant supply chain | compromet une dépendance | Oui, par réduction du périmètre |
| Attaquant physique | cold boot, evil maid, DMA | Non (voir §6) |
| Attaquant quantique | capacité de calcul quantique réaliste | Partiel (voir §5) |

## 4. Propriétés de sécurité visées

- **Confidentialité** : sans la passphrase, le contenu est illisible.
- **Intégrité** : toute modification du fichier (même 1 bit) est détectée et refuse le déchiffrement.
- **Authenticité** : seul qui connaît la passphrase peut produire un fichier valide.
- **Anti-oracle** : rien dans le fichier ne permet de tester un mot de passe plus vite qu'un déchiffrement complet.
- **Pas de fuite mémoire** : les secrets sont effacés (zeroization) après usage, dans la mesure où Rust le permet.

## 5. Choix cryptographiques figés (v1)

| Élément | Choix | Justification |
| --- | --- | --- |
| Dérivation de clé (KDF) | Argon2id, m=64 MiB (65536 KiB), t=3, p=1 | OWASP 2026, résiste GPU/ASIC et side-channels |
| Sel | 32 octets, CSPRNG de l'OS | Unique par coffre, anti-rainbow |
| Chiffrement | XChaCha20-Poly1305 | Constant-time en pur logiciel, nonce 192 bits (anti-réutilisation) |
| Clé | 256 bits, sortie du KDF | Symétrique, résiste à Grover (~128 bits effectifs) |
| Intégrité | Tag Poly1305 (16 octets), AAD = en-tête complet | L'AEAD authentifie enveloppe et contenu ensemble |
| Vérification de mot de passe | Aucune "key check value" en clair | Évite un oracle ; seul le tag AEAD tranche |
| Générateur aléatoire | CSPRNG de l'OS (getrandom) | Jamais de PRNG maison |

Réserves (non utilisées en v1, à activer si le besoin apparaît) :

- intégrité externe ou hachage : SHA-256 (ou BLAKE3, ou SHA-3) ;
- asymétrie post-quantique : ML-KEM-768 (FIPS 203) + ML-DSA (FIPS 204) en mode hybride ;
- signatures d'artefacts : Sigstore/cosign.

### Note quantique

Le cœur est du symétrique : Argon2id (KDF à base de hash) et ChaCha20 (256 bits). L'algorithme
de Grover ne réduit la sécurité que de moitié (~128 bits effectifs), ce qui reste hors de portée.
La fragilité quantique (Shor) ne touche que l'asymétrie, absente de la v1. Si on en ajoute, on passera
en post-quantique hybride.

## 6. Menaces couvertes et contre-mesures

| Menace | Contre-mesure |
| --- | --- |
| Brute force de la passphrase | Argon2id à coût élevé (~250 ms par tentative) |
| Lecture directe du fichier | AEAD : illisible sans la clé |
| Modification/corruption du fichier | Tag Poly1305 : toute altération est refusée |
| Réutilisation de nonce | Nonce 192 bits aléatoire (XChaCha20) |
| Fuite mémoire des secrets | Zeroization explicite, structures à accès confiné |
| Supply chain (typosquat, slop squat, backdoor type XZ) | Zéro dépendance ou quasi, pinning strict, builds reproductibles, review humaine |
| Oracle de vérification | Pas de valeur de contrôle en clair dans l'en-tête |
| Crash pendant l'écriture | Écriture atomique (fichier temporaire + rename) |
| Side-channels logiciels (timing/cache) | ChaCha20 constant-time ; Argon2id résistant par conception |

## 7. Menaces explicitement hors périmètre

Ces menaces ne sont PAS couvertes, et on l'assume par écrit :

- **attaquant root sur la machine en cours d'usage** (peut hooker le process, lire la RAM, keylogger) ;
- **keylogger matériel ou logiciel** déjà installé ;
- **cold boot / DMA** (lecture de la RAM résiduelle) ;
- **evil maid** (altération du matériel ou du logiciel entre deux usages) ;
- **déni de service physique** ou destruction du fichier sans sauvegarde.

Aucun coffre logiciel ne peut se défendre contre un attaquant qui contrôle déjà la machine.
Notre promesse est la suivante : si la machine est saine au moment de l'usage, le fichier peut
traîner n'importe où sans que rien ne fuie.

## 8. Règles d'ingénierie (le harness)

- **Zéro dépendance** par défaut. Toute dépendance ajoutée exige une justification écrite et un audit.
- **Zéro `unsafe`** (ou confiné et justifié ligne à ligne).
- Primitives validées par **test vectors officiels** (RFC 9106 pour Argon2, RFC 8439 pour ChaCha20-Poly1305).
- **Property-based testing** (proptest), **fuzzing** (cargo-fuzz), **Miri**, **sanitizers** (ASan/UBSan) en CI.
- **Builds reproductibles** : lockfile committé, builds hermétiques.
- **Revue humaine obligatoire** : aucun diff IA ne fusionne sans lecture ligne à ligne.
- Chaque bug corrigé devient un **test de régression** permanent.
- Tout changement de ce document suit le même processus de revue que le code.
