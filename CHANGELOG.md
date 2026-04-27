# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file is automatically maintained by
[release-please](https://github.com/googleapis/release-please) on tagged releases.
Direct edits should be limited to fixing typos and syncing "Unreleased" with
what is actually merged on `main`.

## [Unreleased]

### Added (Phase I -- Build & distribution finale)

- **`.github/workflows/release.yml`**: full cross-platform release
  pipeline triggered on `release: published`. Six jobs:
  `sidecar` (PyInstaller matrix Linux + Windows + macOS Intel +
  macOS ARM), `tauri` (NSIS + MSI + DMG + DEB bundles consuming
  the sidecar artefact), `smoke-installer` (silent NSIS install +
  validation), `nfr-verification` (NFR-3 GUI + NFR-4 RSS + NFR-5
  size, fails on regression), `sbom` (cyclonedx-bom for Python +
  npm), `publish` (SHA-256 SUMS + assets uploaded to the GH
  Release).
- **ADR-0018**: Self-signed Authenticode dev cert as the academic
  signing strategy, with documented limits (SmartScreen warning
  on non-demo machines), CI signing step gated on the
  `WINDOWS_CERT_PFX_BASE64` secret, demo machine prep
  instructions, and explicit triggers for upgrading to OV/EV.
- **`scripts/verify_nfr.py`**: reproducible NFR-3/4/5 measurement.
  CLI cold start (5-run median), GUI cold start (3-run median via
  the Tauri spawn -> sidecar handshake proxy), sidecar idle RSS
  via psutil, sidecar + GUI binary size. Emits Markdown by
  default or JSON for CI ingestion; non-zero exit on regression.
- **`docs/NFR_VERIFICATION.md`**: cross-reference of every NFR-X
  to its enforcing test, script, or CI gate. Reflects the
  measured CLI cold-start gap (200 ms target unreachable from
  `python -m guardiabox` dev path; tracked toward ADR-0012's
  Nuitka migration).
- **`docs/security-audits/2026-04-27-final-pre-release.md`** (Z-
  Audit-Final): bandit clean, pip-audit clean, pnpm audit clean
  after the dependency bump documented inline, build pipeline
  STRIDE review.

### Changed (Phase I)

- **Frontend dev dependencies bumped** to clear five known
  advisories (1 critical + 2 high + 2 moderate) flagged by
  `pnpm audit`:
  - `happy-dom` ^15.11.7 -> ^20.0.0 (VM Context Escape RCE +
    fetch-credentials cross-origin + ESM compiler unsanitised
    export names).
  - `vite` ^6.0.3 -> ^7.0.0 (transitive `esbuild` >= 0.25 patches
    the dev-server CORS bypass).
  - `vitest` ^2.1.8 -> ^3.0.0 (compatible with happy-dom 20).
  - `@vitest/{coverage-v8, ui}` ^2.1.8 -> ^3.0.0.
  - **Storybook removed entirely** (last `uuid` moderate via
    `@storybook/addon-actions`). The project never wrote a single
    `*.stories.*` file in Phase H; carrying ~600 transitive deps
    for unused tooling was a free vulnerability surface.
- **`pnpm-lock.yaml` committed** (closes H-17). The frontend CI
  pipeline can now run `pnpm install --frozen-lockfile` for
  reproducibility, and `pnpm audit` becomes a CI gate.
- **`vite.config.ts > test.exclude`** -- vitest now skips
  `tests-e2e/`. Playwright specs were colliding with vitest's
  default include glob and breaking `pnpm test`.

### Added (Phase H — spec 000-tauri-frontend partial)

- **React 19 + Vite 6 desktop UI** running inside the Tauri 2
  WebView2 window. Mirrors the CLI / TUI surface (lock /
  dashboard / encrypt / decrypt / share / accept / history /
  users / settings) over the Phase G sidecar HTTP API.
- **Typed API client** (`src/api/`): hand-written TypeScript
  views matching every Phase G Pydantic schema, a thin fetch
  wrapper auto-injecting `X-GuardiaBox-Token` (via the Tauri
  `get_sidecar_connection` command) and `X-GuardiaBox-Session`
  (via the Jotai `sessionIdAtom`), and TanStack Query hooks
  for every endpoint.
- **State management split** (ADR-0017 candidate): Jotai atoms
  for fine-grained lock state (sessionId, expiresAtMs,
  isUnlocked, activeUserId), Zustand for UI globals (language
  with localStorage persistence + i18next bridge), TanStack
  Query for server cache.
- **AuthGuard + auto-lock**: `useAutoLock` ticks at 1 Hz against
  `expiresAtMsAtom`; on expiry it best-effort calls
  `/api/v1/vault/lock`, drops the local atoms, and the
  AuthGuard reroutes to `/lock`.
- **9 file-based TanStack Router routes**: `/`, `/lock`,
  `/dashboard`, `/dashboard/{encrypt, decrypt, share, accept,
  history, users, settings}`. The `/lock` flow handles both
  unlock and init (when the vault is fresh).
- **Anti-oracle preservation** (ADR-0015 propagated to the UI):
  `/decrypt` 422 collapses to a single i18n string
  (`decrypt.anti_oracle_failure`); `/accept` 422 with detail
  `share verification failed` collapses likewise. The
  `share expired` branch is allowed to differ (raised post-
  signature-verify, no leak).
- **2-step share flow**: form -> fingerprint warning -> commit.
  The recipient picker filters out the active user; the warning
  forces the user to verify out-of-band before confirming.
- **i18n FR + EN** (NFR-6): 100+ keys across app/common/
  password/lock/dashboard/encrypt/decrypt/share/accept/history/
  users/settings/errors namespaces. `i18next-browser-language-
  detector` reads `localStorage.guardiabox.lang` then
  `navigator.language`; fallback `fr`.
- **Shared `<PasswordField>`** with no-echo Input + 20-char
  zxcvbn-style strength bar (client-side hint;
  `assert_strong` on the server is the authoritative gate).
- **Vitest scaffolding**: 16 unit tests covering the password
  evaluator, the lock atoms, and the PasswordField component.
- **WCAG 2.2 AA polish** (NFR-7): focus-visible rings on every
  interactive element, `aria-live="polite"` on the strength bar,
  `scope="col"` on the audit table, `aria-label` on icon
  buttons, `prefers-reduced-motion` killed at the
  `index.css` layer.

Follow-ups tracked but **not in this section**: axe-playwright
WCAG audit (H-13) requires browser binaries; Playwright E2E
flows (H-14) require a live sidecar; per-route slowapi
decorators (G-11.b); `pnpm-lock.yaml` commit + CI activation
(H-17) gated on a green local `pnpm install + lint + typecheck
+ test`.

### Added (Phase G follow-ups — G-10/G-16/G-17/G-18/G-19)

- **WebSocket `/api/v1/stream` (G-10)**: per-session pub/sub via
  `StreamHub` (publisher / subscriber pattern with bounded
  `asyncio.Queue` for back-pressure, fan-out across multiple
  subscribers per session). Auth via query string (browser WS
  clients cannot set custom headers); constant-time token
  compare; session validation against the `SessionStore`. Frame
  shape: `{event, operation_id, ...}` with the four states
  `started | progress | done | error`. The error frame carries
  the constant anti-oracle string only (ADR-0016 §C).
- **CI sidecar build matrix (G-16)**: new `sidecar-build-linux`
  job runs `scripts/build_sidecar.py --release`, uploads the
  PyInstaller artefact, and the Rust job downloads it before
  `cargo test`. This unblocks the previously red Rust gate
  (`tauri::generate_context!()` no longer panics on missing
  `externalBin`).
- **Integration test `test_full_lifecycle_init_unlock_users_share_accept` (G-17)**:
  full E2E driver of the sidecar HTTP surface (init → unlock →
  2 users → encrypt → share → accept → audit verify) using
  `fastapi.testclient.TestClient`. Confirms every router
  co-operates and that the hash-chained audit log stays intact
  after a non-trivial sequence of writes.
- **Integration test `test_sidecar_subprocess.py` (G-18)**:
  spawns the bundled PyInstaller binary, parses the
  `GUARDIABOX_SIDECAR=...` handshake line, hits `/healthz`
  with the launch token, and `SIGTERM`s the process. Skips
  cleanly when the binary is absent (CI matrix builds it
  upstream; the dev workstation skip path lets local pytest
  remain green without `--release`).
- **Property tests (G-19)**: Hypothesis on
  `_print_handshake` (every `(port, token)` pair produces a
  parseable strict-format line; the parser rejects any non-
  prefixed input) and on the Pydantic v2 schemas (every
  arbitrary extra field is refused; `kdf` outside the
  `Literal["pbkdf2", "argon2id"]` is refused). Locks the
  Python/Rust contract at the property level.
- **Coverage gate `src/guardiabox/ui/tauri/sidecar` ≥ 90 %**:
  added to `scripts/check_coverage_gates.py` so a regression
  in the sidecar surface fails CI rather than the global gate.

### Added (Phase G — spec 000-tauri-sidecar partial)

- **FastAPI sidecar bound 127.0.0.1 only** (`SidecarSettings.host`
  is `Literal["127.0.0.1"]`; a regression-blocking source-grep test
  refuses any `0.0.0.0` literal in `src/guardiabox/`).
- **Per-launch session token** (32 octets via
  `secrets.token_urlsafe`, ~256 bits of OS-CSPRNG entropy).
  Compared in constant time via `hmac.compare_digest`. Transported
  via `X-GuardiaBox-Token` header. Whitelist for `/healthz`,
  `/readyz`, `/version`, `/openapi.json`.
- **Vault session model**: in-memory `SessionStore` keyed by
  random `session_id`, TTL = `auto_lock_minutes`, sliding expiry on
  access, zero-fill on close / expiry / lifespan-shutdown. Uses
  the `X-GuardiaBox-Session` header.
- **`vault.admin.json` schema v2** with `verification_blob`: an
  AES-GCM ciphertext sealed under the admin key. Successful decrypt
  proves the password derives the right key, eliminating the
  "wrong-password = different-key" footgun. Pre-1.0 vaults must be
  re-initialised.
- **HTTP endpoints**:
  - `POST /api/v1/init` — bootstrap fresh vault (admin config +
    Alembic migrations + `system.startup` audit row).
  - `POST /api/v1/vault/{unlock,lock}` + `GET /api/v1/vault/status`.
  - `GET/POST/DELETE /api/v1/users` — multi-user CRUD with
    `user.create` / `user.delete` audit hooks.
  - `GET /api/v1/audit` (filterable, decrypted target + actor
    username) and `GET /api/v1/audit/verify` (hash-chain integrity
    probe).
  - `POST /api/v1/encrypt` + `POST /api/v1/decrypt` — file-mode
    delegation to `core.operations` with anti-oracle propagation
    (ADR-0015, sec C of ADR-0016): post-KDF failures collapse to
    HTTP 422 + constant body `{"detail":"decryption failed"}`,
    byte-identical between wrong-password and tampered tag.
  - `POST /api/v1/share` + `POST /api/v1/accept` — hybrid
    RSA-OAEP-SHA256 wrap + RSA-PSS-SHA256 sign over `.gbox-share`
    v1; recipient-side `IntegrityError` collapses to HTTP 422
    `{"detail":"share verification failed"}`.
  - `POST /api/v1/inspect` — read-only `.crypt` header view.
  - `POST /api/v1/secure-delete` — DoD overwrite-dod with SSD
    confirm gate. Crypto-erase mode roadmapped as a follow-up.
  - `GET /api/v1/doctor` — paths + SQLCipher availability + opt-in
    SSD report + opt-in audit chain verify.
  - `GET /healthz` / `/readyz` / `/version` — public probes.
- **slowapi rate-limit scaffolding** (per-IP buckets per ADR-0016
  sec D: 5/min on unlock, 60/min on writes, 30/min on CRUD,
  600/min on read-only). Per-route decorators land in a follow-up;
  `Limiter` instance + 429 constant exception handler are bound on
  app construction.
- **PyInstaller `scripts/build_sidecar.py`** — real invocation
  (`--collect-all guardiabox / cryptography / sqlalchemy / alembic`,
  hidden-imports `argon2._ffi`, `aiosqlite`, `zxcvbn`,
  `--noconsole` on Windows). Optional `--smoke-test` flag spawns
  the produced binary, parses the handshake, hits `/healthz`.
- **Rust shell `sidecar.rs`** — spawn + handshake parse
  (10s timeout, strict prefix `GUARDIABOX_SIDECAR=<port> <token>`,
  rejects zero port / empty token / oversized port). Exposes the
  `get_sidecar_connection` Tauri command. Six Rust unit tests on
  the parser.
- **`tauri.conf.json bundle.externalBin`** restored.
- **ADR-0016** — Tauri sidecar IPC security (per-launch token,
  session model, anti-oracle, slowapi rate limit, no TLS on
  loopback, hard-coded 127.0.0.1 bind).
- 50+ unit tests via `fastapi.testclient.TestClient` covering
  every router, anti-oracle byte-identity on `/decrypt` and
  `/accept`, session TTL slide, zero-fill on close, bind-address
  invariant. ruff strict + mypy strict + bandit clean on the
  sidecar package.

Follow-ups tracked but **not in this section**: WebSocket
`/api/v1/stream` (G-10), CI matrix sidecar build (G-16), full
subprocess spawn integration tests (G-18), per-route rate limit
decorators (G-11.b), crypto-erase variant of `/secure-delete`.

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
- GUI Tauri 2 desktop shell + React 19 frontend (specs
  `000-tauri-sidecar` + `000-tauri-frontend`). Python sidecar bound
  to `127.0.0.1` via per-launch session token; spawned by the Rust
  shell from a PyInstaller bundle declared in `tauri.conf.json
  bundle.externalBin`. Frontend mirrors the CLI/TUI surface
  (lock / dashboard / encrypt / decrypt / share / accept / history /
  users / settings) with i18n FR + EN and WCAG 2.2 AA accessibility.

[Unreleased]: https://github.com/sachamarlov/crypto-sidecar/compare/v0.0.0...HEAD
