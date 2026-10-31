# Security policy

## Status

`coffre` is **pre-alpha**. It has not been audited and must not store critical secrets.
The primitives are validated by cross-validation, but the whole has not undergone an external
audit.

## Reporting a vulnerability

Please do **not** open a public issue for a security vulnerability.

- GitHub: **Security** tab → **Report a vulnerability** (private advisory).
- Email: `jbdev31@gmail.com`, subject `[coffre security]`.

Please include:

- a description of the vulnerability and its impact;
- reproduction steps or a proof of concept;
- the affected version or commit;
- your name or handle if you want to be credited.

## Scope

Covers in particular: file format, encryption, key derivation, atomic writes, zeroization,
CLI and `run` mode.

Out of scope (accepted, see [`THREAT_MODEL.md`](THREAT_MODEL.md)): root attacker on the machine
during use, keylogger, cold boot, evil maid, exposure of a child process environment in `run`
mode, `COFFRE_PASSPHRASE` visible in the process environment.

## Timelines

- Acknowledgement within 7 days.
- Fix or plan within 30 days for confirmed vulnerabilities, depending on severity.
- Coordinated disclosure after the fix is published.

## No bug bounty

Volunteer project, no financial reward. Credit in the advisory if desired.
