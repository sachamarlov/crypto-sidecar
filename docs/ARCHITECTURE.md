# ARCHITECTURE — Technical vision

## 1. Guiding principles

1. **Hexagonal architecture** (Ports & Adapters). Dependencies always point
   inward toward `core/`; UIs and storage are interchangeable adapters.
2. **Single responsibility per module.** Crypto, persistence, UI, and policy
   are not allowed to leak into each other.
3. **Type-strict everywhere** (`mypy --strict` / TypeScript `strict: true`).
4. **Pure functions in `core/`** whenever possible; side effects live at
   boundaries (`fileio/`, `persistence/`, UI, sidecar).
5. **Versioned interfaces** — the `.crypt` container, the sidecar HTTP API,
   and the SQLite schema all carry explicit version markers and migration
   paths.

## 2. Component diagram

```
                                ┌──────────────────────────────┐
                                │ Browser / WebView2 (rendered │
                                │ inside Tauri shell window)   │
                                │   • React 19 + Vite          │
                                │   • shadcn / Aceternity / FM │
                                └──────────────┬───────────────┘
                                               │ fetch (loopback HTTP)
                                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         guardiabox.exe (Tauri shell)                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Tauri 2 (Rust)                                                  │  │
│  │  ─ frameless transparent window, system tray, global shortcuts   │  │
│  │  ─ spawns Python sidecar; bridges stdout for token + port        │  │
│  │  ─ exposes Tauri commands (file dialog, FS, notifications)       │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ child process + stdio
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│             Python sidecar  (FastAPI on 127.0.0.1:random)              │
│                                                                       │
│  ┌──────────────┐ ┌─────────────────┐ ┌──────────────────────────┐    │
│  │ guardiabox   │ │ guardiabox      │ │ guardiabox                │   │
│  │  .ui.cli     │ │  .ui.tui        │ │  .ui.tauri.sidecar        │   │
│  │  (Typer)     │ │  (Textual)      │ │  (FastAPI)                │   │
│  └──────┬───────┘ └─────────┬───────┘ └─────────┬─────────────────┘    │
│         │                   │                    │                    │
│         └───────────────────┴────────────────────┘                    │
│                             │                                          │
│                             ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ guardiabox.security  — password policy, keystore, audit          │ │
│  └────┬─────────────────────────────────────────────────────────┬──┘ │
│       ▼                                                         ▼    │
│  ┌───────────────────────────┐    ┌───────────────────────────────┐  │
│  │ guardiabox.persistence    │    │ guardiabox.fileio             │  │
│  │ SQLAlchemy 2 + SQLCipher  │    │ safe paths, atomic, streaming │  │
│  └───────────┬───────────────┘    └───────────┬───────────────────┘  │
│              ▼                                ▼                       │
│  ┌──────────────────────────────────────────────────────────────────┐│
│  │                     guardiabox.core                              ││
│  │   crypto · kdf · container · secure_delete · constants · errors  ││
│  │              (pure, no I/O, framework-agnostic)                  ││
│  └──────────────────────────────────────────────────────────────────┘│
└────────────────────────────────────────────────────────────────────────┘
```

## 3. Process model

- **One** Tauri shell process — owns the WebView2, system tray, Tauri commands.
- **One** Python sidecar process — owns the FastAPI app, the SQLite DB, and
  any background tasks.
- **One** WebView2 process tree (managed by the OS) — runs the React UI.

The shell and the sidecar communicate exclusively over loopback HTTP. The
shell discovers the sidecar's port and session token by reading the sidecar's
stdout at startup.

## 4. Critical flows

### 4.1 Encrypt a file (CLI path)

```
User                CLI (Typer)            core.crypto/kdf       fileio
 │ encrypt foo.pdf      │                          │                │
 ├─────────────────────►│                          │                │
 │                      │ resolve_within(foo.pdf, cwd)              │
 │                      ├─────────────────────────►│                │
 │                      │◄─ resolved path ─────────┤                │
 │                      │                          │                │
 │ password prompt      │                          │                │
 │◄─────────────────────┤                          │                │
 │ ******               │                          │                │
 ├─────────────────────►│ assert_strong(password)                   │
 │                      │                          │                │
 │                      │ kdf.derive(password, salt, 32)            │
 │                      ├─────────────────────────►│                │
 │                      │◄─ key ──────────────────┤                 │
 │                      │                          │                │
 │                      │ open(target.crypt, 'wb') ─────────────────►│
 │                      │ write_header(...)                          │
 │                      │ for chunk in iter_chunks(foo.pdf):         │
 │                      │   AESGCM.encrypt(key, nonce_i, chunk) ───►│
 │                      │ atomic.commit() ──────────────────────────►│
 │ ✓ Encrypted          │                          │                │
 │◄─────────────────────┤                          │                │
```

### 4.2 GUI flow (Tauri shell ↔ sidecar)

```
React app (browser)         Tauri Rust shell        Python sidecar
 │  POST /api/v1/encrypt          │                       │
 ├──── via fetch ────────────────►│                       │
 │                                │ inject session token  │
 │                                ├──────────────────────►│
 │                                │                       │ verify token
 │                                │                       │ run encrypt flow
 │                                │                       │ stream progress over WebSocket
 │                                │◄──── 200 OK ──────────┤
 │ ◄────── result ────────────────┤                       │
```

## 5. The `.crypt` container format (v1)

| Offset | Size | Field                                            |
| ------ | ---- | ------------------------------------------------ |
| 0      | 4    | Magic bytes `b"GBOX"`                            |
| 4      | 1    | Format version (`0x01`)                          |
| 5      | 1    | KDF identifier (`0x01` PBKDF2 / `0x02` Argon2id) |
| 6      | 2    | KDF params length `N` (big-endian uint16)        |
| 8      | N    | KDF params (algorithm-specific TLV)              |
| 8+N    | 16   | Salt                                             |
| 24+N   | 12   | Base nonce                                       |
| 36+N   | rest | Ciphertext stream (chunked, per-chunk tagged)    |

Implementation rationale and per-chunk-nonce derivation are documented in
[`CRYPTO_DECISIONS.md`](CRYPTO_DECISIONS.md).

## 6. Persistence schema (SQLite, dual encryption backend)

The schema is identical regardless of backend; only the **at-rest
encryption mechanism** differs by platform (see ADR-0011).

### 6.1 Storage backends

| Platform                  | Backend                                             | Coverage                                                                                                                                                     |
| ------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Linux (default)           | **SQLCipher** via `sqlcipher3-binary`               | Every page (B-tree indices, slack space, free pages). Strongest.                                                                                             |
| Windows / macOS (default) | **Column-level AES-GCM** at the repository boundary | Sensitive columns only (filename, original_path, audit_log.target, audit_log.metadata) ; deterministic HMAC index on encrypted columns for equality lookups. |
| Windows / macOS (opt-in)  | **SQLCipher** via `sqlcipher3` (source build)       | Equivalent to Linux ; requires `vcpkg`/`brew` + `uv sync --extra sqlcipher-source`.                                                                          |

The engine is selected at process start: `try: import sqlcipher3` →
SQLCipher engine ; otherwise vanilla SQLite + the column-level wrappers
in `core.crypto.{encrypt_column,decrypt_column}`.

### 6.2 Tables

- **users** — id, username, salt, wrapped vault key, wrapped RSA private,
  RSA public PEM, KDF id + params, timestamps, lockout counters.
- **vault_items** — id, owner_user_id, original filename (encrypted on
  Win/Mac), encrypted size, KDF id, container path on disk, sha256 of
  ciphertext, timestamps.
- **shares** — id, vault_item_id, sender_user_id, recipient_user_id,
  wrapped data-encryption-key (RSA-OAEP), expires_at, accepted_at.
- **audit_log** — sequence (PK), actor_user_id, action, target (encrypted
  on Win/Mac), metadata (encrypted on Win/Mac), prev_hash, entry_hash.
  Append-only enforced via SQL trigger.

Migrations are managed by Alembic (`src/guardiabox/persistence/migrations/`).

## 7. Build & distribution pipeline

```
                        ┌─────────────┐
                        │ uv sync     │ install Python deps from uv.lock
                        └──────┬──────┘
                               ▼
                     ┌─────────────────┐
                     │ uv run pytest   │ tests + coverage
                     └────────┬────────┘
                              ▼
              ┌───────────────────────────────┐
              │ pyinstaller (sidecar)         │ → guardiabox-sidecar.exe
              └───────────────┬───────────────┘
                              │ bundled inside Tauri resources/
                              ▼
                  ┌────────────────────────┐
                  │ pnpm tauri build       │
                  └────────────┬───────────┘
                               ▼
                     ┌─────────────────┐
                     │ guardiabox.exe  │ ≈ 15 MiB Tauri shell
                     │   bundles:      │ + ≈ 25 MiB sidecar
                     │   - WebView2    │ ≈ 40 MiB total (compressed)
                     │   - sidecar.exe │
                     │   - frontend    │
                     └─────────────────┘
```

GitHub Actions runs the same pipeline on every PR; release artefacts are
uploaded on tag push (`release-please`).
