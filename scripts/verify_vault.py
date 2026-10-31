#!/usr/bin/env python3
"""Independent coffre vault verifier (format v1).

Written independently from the Rust code, following FORMAT.md:
- key derivation with argon2-cffi (reference C implementation);
- decryption with PyNaCl (libsodium);
- payload decoding per the documented format.

It is meant to verify that a vault produced by `coffre` matches the spec. It shares
no code with the Rust implementation.

Usage:
  COFFRE_PASSPHRASE=... .venv/bin/python scripts/verify_vault.py <vault> [--show-values]
"""

from __future__ import annotations

import getpass
import os
import struct
import sys

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt

MAGIC = b"COFFRE\x00\x00"
VERSION = 1
KDF_ARGON2ID = 1
HEADER_LEN = 79
KEY_LEN = 32

MAX_M_COST = 524_288
MAX_T_COST = 10
MAX_P_COST = 16


def _take(data: bytes, pos: int, size: int) -> tuple[bytes, int]:
    end = pos + size
    if end > len(data):
        raise ValueError("truncated payload")
    return data[pos:end], end


def parse_header(raw: bytes) -> dict:
    if len(raw) < HEADER_LEN:
        raise ValueError("file too short for a header")
    header = raw[:HEADER_LEN]
    if header[:8] != MAGIC:
        raise ValueError("bad magic")
    (version,) = struct.unpack(">H", header[8:10])
    if version != VERSION:
        raise ValueError(f"unsupported version {version}")
    kdf_id = header[10]
    if kdf_id != KDF_ARGON2ID:
        raise ValueError(f"unsupported kdf id {kdf_id}")
    m_cost, t_cost, p_cost = struct.unpack(">III", header[11:23])
    if (
        not (8 * p_cost <= m_cost <= MAX_M_COST)
        or not (1 <= t_cost <= MAX_T_COST)
        or not (1 <= p_cost <= MAX_P_COST)
    ):
        raise ValueError("unsupported Argon2 parameters")
    return {
        "raw": header,
        "version": version,
        "kdf_id": kdf_id,
        "m_cost": m_cost,
        "t_cost": t_cost,
        "p_cost": p_cost,
        "salt": header[23:55],
        "nonce": header[55:79],
    }


def derive_key(passphrase: str, header: dict) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode(),
        salt=header["salt"],
        time_cost=header["t_cost"],
        memory_cost=header["m_cost"],
        parallelism=header["p_cost"],
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def decrypt(header: dict, body: bytes, passphrase: str) -> bytes:
    key = derive_key(passphrase, header)
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        body, header["raw"], header["nonce"], key
    )


def decode_payload(data: bytes) -> dict[str, bytes]:
    pos = 0
    raw_count, pos = _take(data, pos, 4)
    (count,) = struct.unpack(">I", raw_count)
    entries: dict[str, bytes] = {}
    for _ in range(count):
        raw_len, pos = _take(data, pos, 4)
        (name_len,) = struct.unpack(">I", raw_len)
        raw_name, pos = _take(data, pos, name_len)
        name = raw_name.decode("utf-8")
        raw_len, pos = _take(data, pos, 4)
        (value_len,) = struct.unpack(">I", raw_len)
        value, pos = _take(data, pos, value_len)
        if name in entries:
            raise ValueError(f"duplicate name: {name}")
        entries[name] = value
    if pos != len(data):
        raise ValueError("trailing data")
    return entries


def main() -> int:
    args = sys.argv[1:]
    show_values = "--show-values" in args
    args = [arg for arg in args if arg != "--show-values"]
    if len(args) != 1:
        print("usage: verify_vault.py <vault> [--show-values]", file=sys.stderr)
        return 2

    with open(args[0], "rb") as handle:
        raw = handle.read()

    header = parse_header(raw)
    body = raw[HEADER_LEN:]

    passphrase = os.environ.get("COFFRE_PASSPHRASE")
    if passphrase is None:
        passphrase = getpass.getpass("Passphrase: ")

    try:
        plaintext = decrypt(header, body, passphrase)
    except Exception as exc:
        print(f"FAIL: decryption failed ({exc})", file=sys.stderr)
        return 1

    entries = decode_payload(plaintext)
    print("OK: vault matches format v1")
    print(
        f"  version={header['version']} kdf=Argon2id "
        f"m_cost={header['m_cost']} t_cost={header['t_cost']} p_cost={header['p_cost']}"
    )
    for name in sorted(entries):
        value = entries[name]
        if show_values:
            print(f"  {name} = {value!r}")
        else:
            print(f"  {name} ({len(value)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
