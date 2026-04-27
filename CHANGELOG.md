# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file is automatically maintained by
[release-please](https://github.com/googleapis/release-please) on tagged releases.
Direct edits should be limited to fixing typos and syncing "Unreleased" with
what is actually merged on `main`.

## [Unreleased]

### Added
- **Spec 001** — file and message encryption with AES-256-GCM and a
  choice of PBKDF2-HMAC-SHA256 (≥ 600 000 iterations) or Argon2id
  (m ≥ 64 MiB, t ≥ 3, p ≥ 1). Chunk-bound AAD (header || index ||
  is_final) binds every ciphertext chunk to the header and its position
  — protects against truncation, reordering, and header substitution
  (ADR-0014).
- **Spec 002** — decryption with byte-identical stderr / exit code
  between wrong-password and tampered ciphertext. Anti-oracle property
  verified by subprocess-level tests (ADR-0015).
- **Spec 004 Phase B1** — secure deletion via DoD 5220.22-M multi-pass
  overwrite + cross-platform SSD detection (Windows IOCTL, Linux
  `/sys/block`, macOS `diskutil`).
- CLI: `encrypt`, `decrypt`, `inspect`, `secure-delete` sub-commands
  with POSIX exit codes (0/1/2/3/64/65/130).
- 16 ADRs (MADR v4) documenting every architectural decision.
- **Spec 000-multi-user Phase C-1** — persistence foundations:
  SQLAlchemy 2.0 async models (`User`, `VaultItem`, `Share`,
  `AuditEntry`), column-level AES-GCM encryption with HMAC indices
  for lookup on encrypted columns (ADR-0011 fallback path),
  Alembic initial migration with append-only triggers on
  `audit_log`, async engine + `session_scope`, concrete
  `UserRepository` / `VaultItemRepository` / `ShareRepository` /
  `AuditRepository`, keystore `create` / `unlock` /
  `change_password` (RSA-4096 + AES-256 vault key), audit
  hash-chain `append` / `verify` with byte-identical tamper
  detection over ciphertext columns.
- **Spec 000-multi-user Phase C-2** — CLI surface for the multi-user
  vault: `guardiabox init` bootstrap (creates `data_dir`, writes
  `vault.admin.json`, runs Alembic, appends `system.startup` to
  the audit chain), `guardiabox user create / list / show / delete`,
  `guardiabox history --limit --user --action --format table|json`,
  `guardiabox doctor [--verify-audit]` with `[OK] / [FAIL]` chain
  reporting, opt-in `--vault-user <name>` flag on
  `encrypt` / `decrypt` that records the action in the audit log
  (and, for encrypt, persists a `vault_items` row).

### Added (Phase D — spec 003 RSA-share)
- **Spec 003 — hybrid RSA-OAEP / AES-GCM share between local users.**
  `core/rsa.py` exposes `RsaWrap.wrap/unwrap` (RSA-OAEP-SHA256) and
  `RsaSign.sign/verify` (RSA-PSS-SHA256, max salt). `core/share_token.py`
  ships the `.gbox-share` v1 binary container (magic `GBSH`, sender +
  recipient UUIDs, content SHA-256, wrapped DEK, expires_at,
  permission flags, embedded ciphertext, RSA-PSS suffix signature).
  `core/operations.py` orchestrates `share_file` / `accept_share`:
  decrypt source → fresh DEK → re-encrypt with AAD `b"guardiabox/share/v1"`
  → wrap DEK for recipient → sign payload → write atomically. Accept
  verifies signature **first** (anti-oracle, ADR-0015 applied to
  share tokens), then recipient match, expiry, content hash, unwrap,
  decrypt, atomic write.
- CLI: `guardiabox share <source.crypt> --from <sender> --to <recipient>`
  with public-key fingerprint display + `[y/N]` confirmation;
  `guardiabox accept <token.gbox-share> --from <sender> --as <recipient>`
  recovers the plaintext. Both append `file.share` /
  `file.share_accept` to the hash-chained audit log.
- Out-of-band fingerprint display defends against AD-2 (local DB
  tampering of recipient's pubkey). `--yes` bypasses for scripts.
- New exception `ShareExpiredError` (raised AFTER signature verify so
  expiry status is not an oracle).
- 53+ tests added: 25 RSA primitive unit + property tests, 17 share-token
  format unit + property tests, 11 integration share/accept (round-trip,
  tampering, recipient mismatch, expiry, anti-oracle), 5 CLI E2E.

### Fixed
- **Secure-delete random pass** — `_pattern_for_pass` previously
  returned a single byte from `secrets.token_bytes(1)` to mark the
  random pass; if that byte happened to be `\x00` or `\xff`
  (≈ 0.78 %) the downstream check mistook the pass for a fixed-fill
  zero/one pass and overwrote the file with that fixed byte instead
  of fresh random bytes. Replaced the byte sentinel with a
  `_PassKind` enum so the random branch is unambiguous. DoD
  5220.22-M pass #3 is now guaranteed random.

### Security
- KDF parameter floors AND ceilings enforced on both encode and decode
  paths — guards against crafted headers that would cause OOM or
  multi-hour CPU exhaustion before failing authentication.
- Path controls reject Windows reparse points (junctions, mount points)
  in addition to POSIX symlinks.
- `source == dest` refused by encrypt/decrypt to prevent destructive
  overwrites (`DestinationCollidesWithSourceError`).
- Passwords NFC-normalised before UTF-8 encoding to prevent
  visually-identical codepoint sequences from deriving distinct keys.
- Atomic writer tears down temp files on `KeyboardInterrupt` as well
  as `Exception` (per CONVENTIONS.md §16, never catches `BaseException`).

### Known roadmap (not yet merged)
- RSA-OAEP hybrid sharing (spec 003) — `share` / `accept` commands
  + `--vault-user` keystore unlock + `Share` row + `file.share`
  audit entry. Will reuse the `--vault-user` flow already shipped.
- Cryptographic erase (spec 004 Phase B2) — depends on a finished
  spec 003 because crypto-erase uses the wrapped DEK held in the
  per-user keystore.
- TUI (spec 000-tui), GUI + Tauri sidecar (spec 000-tauri-sidecar).

[Unreleased]: https://github.com/sachamarlov/crypto-sidecar/compare/v0.0.0...HEAD
