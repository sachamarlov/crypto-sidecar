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

### Added (Phase F — spec 000-tui Textual)
- **TUI complète Textual 8.2.4** (`guardiabox-tui`) :
  - GuardiaBoxApp + 6 screens (Dashboard, Encrypt, Decrypt, Share,
    History, Settings) + 2 widgets réutilisables (PasswordField avec
    zxcvbn live, Toast auto-dismissing)
  - Global bindings : `e/d/s/h/c` pour les modals, `q` quit,
    `Ctrl+L` pour basculer dark/light theme
  - Reduced-motion probe (TERM=dumb ou CI=true) coupe les animations
  - HistoryScreen affiche les 200 dernières entrées audit dans une
    DataTable après prompt admin password
  - SettingsScreen montre la config courante (alignée avec
    `guardiabox config list`)
  - ShareScreen redirige vers la CLI (full TUI wrap post-MVP)
- **Anti-oracle préservé sur DecryptScreen** : `DecryptionError` et
  `IntegrityError` collapsent vers `ANTI_ORACLE_MESSAGE`, même toast
  uniforme.
- 13 tests intégration via `App.run_test()` (DOM tree assertions,
  pas snapshot — `pytest-textual-snapshot` reporté post-MVP).

### Added (Phase E — spec 000-cli residuals)
- **`guardiabox config`** sub-Typer (`list` / `get`). Flattens the
  pydantic-settings tree into dotted keys (e.g.
  `crypto.pbkdf2_iterations`). `set` is deferred post-MVP — users
  override via `GUARDIABOX_<KEY>` env vars or `.env`.
- **Global `--quiet` / `--verbose` flags** on the root callback.
  `--verbose` → structlog DEBUG ; `--quiet` → ERROR + `GUARDIABOX_QUIET=1`
  env var (consumable by future success-line suppression). Mutually
  exclusive with `--verbose`.
- **`--format json|table`** added to `user list`, `user show`, and
  `doctor` (already shipped on `history` in Phase C). All four read
  commands now emit either a Rich-style human table or a parseable
  JSON document — useful for CI smokes, scripts, and the upcoming
  Tauri sidecar surface.

### Added (Phase B2 — spec 004 crypto-erase)
- **`SecureDeleteMethod.CRYPTO_ERASE`** + CLI `secure-delete --method
  crypto-erase --vault-user <name>` — combines the DoD overwrite with a
  vault DB cleanup: looks up the matching `vault_items` row by filename
  HMAC, runs the overwrite, deletes the row, appends a
  `file.secure_delete` audit row. Honest scope documented inline:
  GuardiaBox does not currently persist a per-file DEK separate from the
  `.crypt` payload, so what ships is *metadata-erase + ciphertext
  overwrite + audit attribution*, not a strict NIST SP 800-88
  crypto-erase. The mode rejects calls without `--vault-user`.
- New exceptions `KeyNotFoundError` (vault_items row miss → exit 3) and
  `CryptoEraseRequiresVaultUserError` (mode without `--vault-user` →
  exit 64). Both routed by `ui.cli.io.exit_for`.
- `guardiabox doctor --report-ssd` reports the data_dir's storage type
  (SSD / HDD / unknown) with the relevant recommendation.

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
