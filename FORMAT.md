<p align="center"><a href="FORMAT.fr.md">Français</a> | <strong>English</strong></p>

# File format (v1)

A vault is a single binary file: a cleartext header (authenticated), followed by an encrypted
body. All integers are **big-endian**.

## Header (79 bytes, cleartext, used as AAD)

| Offset | Size | Field | Value |
| --- | --- | --- | --- |
| 0 | 8 | `magic` | `COFFRE\0\0` |
| 8 | 2 | `version` | `1` |
| 10 | 1 | `kdf_id` | `1` (Argon2id) |
| 11 | 4 | `m_cost` | memory in KiB |
| 15 | 4 | `t_cost` | passes |
| 19 | 4 | `p_cost` | parallelism |
| 23 | 32 | `salt` | Argon2 salt |
| 55 | 24 | `nonce` | XChaCha20 nonce |
| 79 | ... | `body` | ciphertext + tag (16 bytes) |

The entire header is passed as **AAD** to the AEAD. Any change to a header byte (params,
salt, nonce, version) invalidates the tag.

## Body

`body = XChaCha20-Poly1305(key, nonce, plaintext, aad = header)`

The Poly1305 tag (16 bytes) is appended to the ciphertext.

## Payload (before encryption)

Deterministic binary serialization of a `name -> value` table:

```
n            : u32
repeated n times:
  name_len   : u32
  name       : name_len bytes (UTF-8)
  value_len  : u32
  value      : value_len bytes (binary)
```

Entries are serialized in sorted name order (`BTreeMap`), so equal content yields an
identical payload.

## Argon2 parameter bounds

The header is read **before** authentication: a crafted file could request an unbounded
derivation. A conforming reader rejects the file, without running Argon2, if:

| Parameter | Accepted bound |
| --- | --- |
| `m_cost` | ≤ 524,288 KiB (512 MiB), and ≥ 8 × `p_cost` (Argon2 minimum) |
| `t_cost` | 1 to 10 |
| `p_cost` | 1 to 16 |

The same bounds apply at creation. Defaults: `m_cost = 65536` (64 MiB), `t_cost = 3`,
`p_cost = 1`.

## Security rules

- `salt`: 32 bytes from the CSPRNG, **unique per vault**, stored in cleartext.
- `nonce`: 24 bytes from the CSPRNG, **fresh on every write**. Never reuse under the same
  key.
- A wrong passphrase and a corrupted file produce the same error (no oracle).
- The payload is deserialized only **after** AEAD tag validation; the parser is still
  panic-free on arbitrary input.
