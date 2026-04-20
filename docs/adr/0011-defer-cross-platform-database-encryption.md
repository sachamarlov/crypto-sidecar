# 0011 — Cross-platform database encryption strategy

* Status: accepted
* Date: 2026-04-20
* Deciders: @sachamarlov, Claude Opus 4.7
* Supersedes: [ADR-0003](0003-sqlcipher-for-database-at-rest.md) (partially)
* Tags: [crypto, persistence, packaging]

## Context and problem statement

ADR-0003 mandated SQLCipher for at-rest encryption of the metadata SQLite
database (filenames, audit log, RSA public keys, KDF parameters, ...).
While implementing the bootstrap CI we hit a hard packaging constraint:

* `sqlcipher3-binary` (the only PyPI distribution shipping pre-built
  SQLCipher wheels) **only publishes Linux x86_64 wheels**.
* On Windows and macOS the user must (i) install SQLCipher via the system
  package manager (`vcpkg install sqlcipher` / `brew install sqlcipher`)
  and (ii) build the Python binding from source (`sqlcipher3` extra).

Forcing Windows users (our primary academic-demo target) to install
vcpkg + a C++ toolchain just to launch GuardiaBox is a UX regression
incompatible with the "double-click and run" goal stated in the README.

At the same time, **leaving the database in the clear on Windows / macOS
is a security regression** that is incompatible with ADR-0003's "defense
in depth" stance — filenames and audit-log entries leak intent even if
the file content (the `.crypt` payloads) remains encrypted.

We need a single decision that ships an acceptable security floor on
*every* platform, without making the install path painful.

## Considered options

* **A. Keep ADR-0003 unchanged**, ship SQLCipher on Linux only, leave
  Windows / macOS users with an unencrypted DB by default.
  → Documented regression. Worst of both worlds.

* **B. Compile SQLCipher in CI** for Windows wheels, host the artefacts
  ourselves (e.g. via a private wheel index or git LFS in `vendor/`).
  → Adds significant build complexity, slows CI by 3-5 minutes per run,
  ties us to vcpkg / brew evolution.

* **C. Layered strategy (chosen)**:
  1. Use SQLCipher whenever it is available (Linux by default, Win/Mac
     when the user opts in via the `sqlcipher-source` extra).
  2. On any platform where SQLCipher is **not** present, fall back to
     **column-level AES-GCM encryption** of the sensitive columns
     (`filename`, `original_path`, `audit_log.target`, `audit_log.metadata`)
     using a key derived from the *vault administrator* password — same
     key derivation we already use for `vault_key`.
  3. The schema is identical in both modes; only the storage backend
     differs. Reads transparently decrypt; writes transparently encrypt.

* **D. Drop database-level encryption entirely** and rely on OS-level
  full-disk encryption (BitLocker, FileVault, dm-crypt).
  → Punts the responsibility to the user. Doesn't survive `cp ~/.guardiabox`
  to an unencrypted external disk.

## Decision

Adopt **option C**.

### Concrete implementation roadmap

| Where | What |
|-------|------|
| `pyproject.toml` | `sqlcipher3-binary>=0.5.4 ; sys_platform == 'linux'` in main `dependencies` (auto-installed on Linux). `sqlcipher3>=0.5.4 ; sys_platform != 'linux'` in optional `sqlcipher-source` extra (opt-in for Win/Mac power users). |
| `src/guardiabox/persistence/database.py` | `create_engine` checks `try: import sqlcipher3` → returns SQLCipher-backed engine if available. Else returns vanilla SQLite engine and the repository layer wraps writes/reads via `core.crypto.encrypt_column / decrypt_column`. |
| `src/guardiabox/core/crypto.py` (spec 002) | New helpers `encrypt_column(plaintext, vault_key, aad) -> bytes` / `decrypt_column(blob, vault_key, aad) -> plaintext`, both using AES-GCM with a per-column random nonce and a strict associated-data binding (`column_name + row_id`) to prevent cross-column ciphertext substitution. |
| `src/guardiabox/persistence/repositories.py` (spec 002) | `UserRepository`, `VaultItemRepository`, `AuditRepository` use the encryption helpers when the engine is vanilla SQLite. Indexed lookups on encrypted columns use a deterministic SHA-256 HMAC for index keys. |
| `docs/THREAT_MODEL.md` | Added section "Database at-rest exposure (Win/Mac without SQLCipher)" + cross-reference to this ADR. |
| `README.md` quickstart | Mention BitLocker / FileVault as a complementary recommendation. |

The **minimum security floor is identical** on every platform: filenames
and audit metadata are never in plaintext on disk, regardless of the
backend selected at runtime. SQLCipher is the preferred path on Linux
because it covers *every* SQLite page (including B-tree indices and
slack space) and benefits from years of focused fuzzing — column-level
encryption protects only the columns we explicitly wrap.

## Consequences

**Positive**

* Zero regression versus ADR-0003 for the most common Linux dev / server
  scenarios (Linux is automatic).
* Windows / macOS users get a working install with **encrypted metadata**
  out of the box, no manual steps required.
* Power users on Win/Mac can opt into SQLCipher for the strongest
  available protection (`uv sync --extra sqlcipher-source`).
* The schema stays identical across backends — no migration needed when
  switching.

**Negative**

* Two storage code paths to maintain (SQLCipher vs column-level).
* Column-level encryption can't index encrypted columns directly: we
  accept HMAC-based deterministic indices for equality lookups, no
  range queries on encrypted columns. Acceptable for our schema.
* The fallback adds ~50 lines of Python in `core/crypto.py` and slightly
  more code per repository call. Tracked as part of spec 002.

## References

* ADR-0003 (superseded by this one for cross-platform behaviour).
* SQLCipher design — https://www.zetetic.net/sqlcipher/design/
* `sqlcipher3-binary` PyPI — https://pypi.org/project/sqlcipher3-binary/
* `sqlcipher3` (source build) — https://pypi.org/project/sqlcipher3/
* OWASP Cryptographic Storage Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
