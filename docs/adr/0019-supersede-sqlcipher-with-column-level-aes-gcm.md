---
status: accepted
date: 2026-04-29
supersedes: ADR-0011
deciders: Sacha Marlov + Claude Opus 4.7 (autonomy mode)
---

# ADR-0019 — Supersede ADR-0011: column-level AES-GCM uniformised across all OS

## Context

ADR-0011 specified a **dual-path** strategy for cross-platform
database encryption:

1. **Linux**: SQLCipher (full-database AES-256-CBC + HMAC-SHA512)
   when `sqlcipher3` is importable.
2. **Windows / macOS / fallback**: column-level AES-GCM on the
   encrypted-by-design columns (`username_enc`, `filename_enc`,
   `target_enc`, `metadata_enc`) plus deterministic HMAC indices
   for lookups.

In practice the async codebase (Phase C) settled on the fallback
path everywhere:

* `persistence/database.py:create_engine` rejects every URL
  except `sqlite+aiosqlite`. The SQLCipher branch was never merged
  into the async path.
* `pyproject.toml` declares `sqlcipher3-binary` as a `[project.
  optional-dependencies]` extra named `sqlcipher-source`, but no
  CI job installs it and the bundled PyInstaller binary does not
  pull it.
* `docs/CRYPTO_DECISIONS.md` §6.1 still claimed "Linux (default) —
  SQLCipher AES-256-CBC". `docs/THREAT_MODEL.md` §6 + §4.4 echoed
  this. `docs/ARCHITECTURE.md` storage table did the same.

The audit (B-D) flagged the divergence at A P0-5: the shipping
code lives one strategy, the docs sell another, and a future
contributor reading the ADR would be misled.

## Decision

**SQLCipher is permanently out of scope.** The single supported
path is column-level AES-GCM via aiosqlite, identical on Linux,
Windows, macOS, and any future POSIX target. ADR-0011 is
superseded.

Rationale for dropping SQLCipher entirely:

* **Uniformity**: identical crypto floor on every OS removes the
  "is SQLCipher loaded?" branch from every threat-model claim.
* **Build complexity**: SQLCipher requires a native C library
  (libsqlcipher), bundled differently per OS; dropping it
  simplifies the PyInstaller bundle, the GitHub Actions matrix,
  and the contributor onboarding.
* **Limit is documented, not hidden**: the audit log columns
  `action`, `actor_user_id`, `timestamp`, `sequence`, `prev_hash`,
  `entry_hash` remain plaintext at rest because the HMAC index
  lookup pattern needs them readable; this is a documented
  acceptable limit (see Threat Model update §6.x). OS-level FDE
  (BitLocker / FileVault / LUKS) is the recommended mitigation.

## Consequences

* `persistence/database.py` keeps the explicit `ValueError` on
  any non-`sqlite+aiosqlite` URL — no future "fallback" branch.
* `sqlcipher_available()` stays as a `doctor` probe but becomes
  purely informational; future contributors who see `True` should
  not infer that GuardiaBox uses it.
* `pyproject.toml` keeps the optional `sqlcipher3-binary` extra
  for downstream forks that *do* want it, but no CI job, no
  PyInstaller bundle, and no docs reference it as a default.
* **Docs sync** (Phase γ-6 closes this): `docs/CRYPTO_DECISIONS.
  md` §6.1, `docs/THREAT_MODEL.md` §6 + §4.4, `docs/ARCHITECTURE.
  md` storage tables now describe column-level AES-GCM as the
  uniform strategy. README mentions SQLCipher only in historical
  notes.
* **Audit trail integrity**: the hash chain in `audit_log` does
  not depend on SQLCipher. Tampering with plaintext columns is
  detected by `verify_audit_chain` regardless.

## Trade-off accepted

A reader of the SQLite file with `sqlite3` CLI access can read:

* `audit_log.action`, `actor_user_id`, `timestamp`, `sequence`
* `users.id`, `created_at`
* `vault_items.id`, `created_at`, `owner_user_id`
* `shares.created_at`, `expires_at`, `accepted_at`

They cannot read filenames, audit targets, audit metadata, RSA
keystores, or vault keys (all column-encrypted under the admin
key). Forensic post-incident is dégradé but not destroyed.

The **Threat Model** §6 and §4.4 are updated to make this
trade-off explicit.

## Migration

No schema migration needed: ADR-0011's column-level path is
already what every existing vault uses. The SQLCipher branch in
the codebase was never reachable at runtime, so no field-side
data lives under SQLCipher today.
