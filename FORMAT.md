<p align="center"><strong>Français</strong> | <a href="FORMAT.en.md">English</a></p>

# Format de fichier (v1)

Un coffre est un fichier binaire unique : un en-tête en clair (authentifié), suivi d'un corps chiffré.
Tous les entiers sont en **big-endian**.

## En-tête (79 octets, en clair, utilisé comme AAD)

| Offset | Taille | Champ | Valeur |
| --- | --- | --- | --- |
| 0 | 8 | `magic` | `COFFRE\0\0` |
| 8 | 2 | `version` | `1` |
| 10 | 1 | `kdf_id` | `1` (Argon2id) |
| 11 | 4 | `m_cost` | mémoire en KiB |
| 15 | 4 | `t_cost` | passes |
| 19 | 4 | `p_cost` | parallélisme |
| 23 | 32 | `salt` | sel Argon2 |
| 55 | 24 | `nonce` | nonce XChaCha20 |
| 79 | ... | `body` | ciphertext + tag (16 octets) |

L'en-tête est passé intégralement comme **AAD** à l'AEAD. Toute modification d'un octet
d'en-tête (params, sel, nonce, version) invalide le tag.

## Corps

`body = XChaCha20-Poly1305(clé, nonce, plaintext, aad = en-tête)`

Le tag Poly1305 (16 octets) est concaténé à la fin du ciphertext.

## Payload (avant chiffrement)

Sérialisation binaire déterministe d'une table `nom -> valeur` :

```
n            : u32
répété n fois :
  name_len   : u32
  name       : name_len octets (UTF-8)
  value_len  : u32
  value      : value_len octets (binaire)
```

Les entrées sont sérialisées dans l'ordre trié des noms (`BTreeMap`), pour un payload
déterministe à contenu égal.

## Bornes des paramètres Argon2

L'en-tête est lu **avant** l'authentification : un fichier piégé pourrait demander une
dérivation démesurée. Un lecteur conforme refuse le fichier, sans lancer Argon2, si :

| Paramètre | Borne acceptée |
| --- | --- |
| `m_cost` | ≤ 524 288 KiB (512 MiB), et ≥ 8 × `p_cost` (minimum Argon2) |
| `t_cost` | 1 à 10 |
| `p_cost` | 1 à 16 |

Les mêmes bornes s'appliquent à la création. Valeurs par défaut : `m_cost = 65536`
(64 MiB), `t_cost = 3`, `p_cost = 1`.

## Règles de sécurité

- `salt` : 32 octets tirés du CSPRNG, **unique par coffre**, stocké en clair.
- `nonce` : 24 octets tirés du CSPRNG, **nouveau à chaque écriture**. Ne jamais réutiliser
  sous la même clé.
- Un mot de passe erroné et un fichier corrompu produisent la même erreur (pas d'oracle).
- Le payload n'est désérialisé qu'**après** validation du tag AEAD ; le parseur reste
  néanmoins sans panique face à une entrée arbitraire.
