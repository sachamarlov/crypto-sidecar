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
- Multi-user vault **Phase C-2**: CLI surface (`user`, `history`,
  `doctor --verify-audit`) + integration with encrypt/decrypt flows
  (spec 000-multi-user tasks T-000mu.09 to T-000mu.13).
- RSA-OAEP hybrid sharing (spec 003).
- Cryptographic erase (spec 004 Phase B2).
- TUI (spec 000-tui), GUI + Tauri sidecar (spec 000-tauri-sidecar).

[Unreleased]: https://github.com/sachamarlov/crypto-sidecar/compare/v0.0.0...HEAD
