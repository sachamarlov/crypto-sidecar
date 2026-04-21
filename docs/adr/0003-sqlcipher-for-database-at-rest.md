# 0003 — Encrypt the SQLite database at rest with SQLCipher

- Status: superseded by [ADR-0011](0011-defer-cross-platform-database-encryption.md) (partially)
- Date: 2026-04-20
- Deciders: @sachamarlov, Claude Opus 4.7
- Tags: [crypto, persistence]

> **Supersession note** — The "SQLCipher everywhere" stance recorded here
> turned out to be unrealistic on Windows / macOS where no PyPI pre-built
> wheel exists. ADR-0011 amends the policy: SQLCipher remains the default
> on Linux, and a column-level AES-GCM fallback covers Win/Mac so the
> metadata-protection floor is preserved on every platform. Read ADR-0011
> alongside this one.

## Context

The metadata DB stores filenames, sizes, KDF identifiers, share metadata,
and the audit log. None of this is the _content_ of user files (which lives
in `.crypt`), but filenames alone leak intent ("tax-fraud-evidence.crypt").
Defence in depth says we should not store cleartext metadata next to
encrypted content.

## Considered options

- **A. Plain SQLite** — fastest, simplest, leaks metadata.
- **B. SQLCipher** — drop-in SQLite replacement that encrypts every page
  with AES-256 and authenticates with HMAC-SHA-512.
- **C. App-level encryption of sensitive columns** — encrypt selectively
  before insertion. Schema becomes harder to query; ad hoc queries still
  leak; more code surface to get wrong.

## Decision

Adopt **option B**. SQLCipher's database key is derived from a vault
administrator password using PBKDF2-SHA256 with the same iteration count as
user keystores.

## Consequences

**Positive**

- Filenames, share metadata, and audit log are unreadable on disk without
  the admin password.
- Standard SQL still works — no query rewriting needed.

**Negative**

- Adds a native dependency (`sqlcipher3-binary`). Wheels available for
  Linux/Windows; macOS requires `brew install sqlcipher` then a source build.
- Slight write overhead (per-page encryption); irrelevant at our scale.

## References

- SQLCipher design — https://www.zetetic.net/sqlcipher/design/
- `sqlcipher3-binary` — https://pypi.org/project/sqlcipher3-binary/
