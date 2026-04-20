# 0003 — Encrypt the SQLite database at rest with SQLCipher

* Status: accepted
* Date: 2026-04-20
* Deciders: @sachamarlov, Claude Opus 4.7
* Tags: [crypto, persistence]

## Context

The metadata DB stores filenames, sizes, KDF identifiers, share metadata,
and the audit log. None of this is the *content* of user files (which lives
in `.crypt`), but filenames alone leak intent ("tax-fraud-evidence.crypt").
Defence in depth says we should not store cleartext metadata next to
encrypted content.

## Considered options

* **A. Plain SQLite** — fastest, simplest, leaks metadata.
* **B. SQLCipher** — drop-in SQLite replacement that encrypts every page
  with AES-256 and authenticates with HMAC-SHA-512.
* **C. App-level encryption of sensitive columns** — encrypt selectively
  before insertion. Schema becomes harder to query; ad hoc queries still
  leak; more code surface to get wrong.

## Decision

Adopt **option B**. SQLCipher's database key is derived from a vault
administrator password using PBKDF2-SHA256 with the same iteration count as
user keystores.

## Consequences

**Positive**

* Filenames, share metadata, and audit log are unreadable on disk without
  the admin password.
* Standard SQL still works — no query rewriting needed.

**Negative**

* Adds a native dependency (`sqlcipher3-binary`). Wheels available for
  Linux/Windows; macOS requires `brew install sqlcipher` then a source build.
* Slight write overhead (per-page encryption); irrelevant at our scale.

## References

* SQLCipher design — https://www.zetetic.net/sqlcipher/design/
* `sqlcipher3-binary` — https://pypi.org/project/sqlcipher3-binary/
