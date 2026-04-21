# 000 — Tauri sidecar — technical plan

## Touched modules

- `guardiabox.ui.tauri.sidecar.main` — entry point ; binds 127.0.0.1,
  picks free port, generates session token, prints handshake line,
  starts Uvicorn.
- `guardiabox.ui.tauri.sidecar.api.v1.{encrypt,decrypt,share,users,
audit,health}` — FastAPI routers, one module per resource.
- `guardiabox.ui.tauri.sidecar.api.middleware` — token authentication
  middleware ; rejects every request without the `X-GuardiaBox-Token`
  header set to the launch-generated token.
- `guardiabox.ui.tauri.sidecar.api.schemas` — Pydantic v2 models for
  request / response bodies.
- `guardiabox.ui.tauri.sidecar.api.ws` — WebSocket endpoint for
  progress streaming (one connection per UI session).
- `scripts/build_sidecar.py` — real PyInstaller invocation (replaces
  the current stub).
- `src/guardiabox/ui/tauri/src-tauri/src/sidecar.rs` — Rust shell side:
  spawn the binary, parse the handshake line, store `(port, token)`
  in shared state, expose `get_sidecar_connection()` Tauri command.

## Architecture

```
guardiabox.exe (Tauri Rust shell)
    │ spawn child process
    ▼
guardiabox-sidecar.exe  (PyInstaller-bundled FastAPI)
    │ stdout line: "GUARDIABOX_SIDECAR=<port> <token>\n"
    │
    └─► uvicorn on 127.0.0.1:<port>
        ┌───────────────────────────────────────────────┐
        │ Middleware: token check                       │
        │ Routers: /api/v1/{encrypt,decrypt,share,...}  │
        │ WebSocket: /api/v1/stream                     │
        │ /healthz, /readyz, /version                   │
        └───────────────────────────────────────────────┘
            │ direct calls (no further IPC)
            ▼
        guardiabox.core / guardiabox.security / guardiabox.persistence
```

## Security guarantees

- Bind address is hard-coded to `127.0.0.1`. A test asserts the
  process never opens `0.0.0.0` or any non-loopback socket.
- Session token is generated with `secrets.token_urlsafe(32)` (256
  bits of entropy) and stored only in process memory + sidecar stdout.
- CSP on the Tauri side (already configured) restricts `connect-src`
  to `http://127.0.0.1:*` and `ws://127.0.0.1:*`.
- The audit log receives entries for every state-changing API call,
  with the actor inferred from the unlocked user context.

## PyInstaller invocation

```bash
pyinstaller \
    --onefile \
    --noconsole \
    --name guardiabox-sidecar-${TARGET_TRIPLE} \
    --collect-all guardiabox \
    --collect-all cryptography \
    --collect-all sqlalchemy \
    --hidden-import argon2 \
    --hidden-import sqlcipher3 \
    --distpath src/guardiabox/ui/tauri/src-tauri/binaries \
    --workpath build/pyinstaller \
    --specpath build/pyinstaller \
    src/guardiabox/ui/tauri/sidecar/main.py
```

The CI matrix runs this on each OS (Windows, Linux, macOS) and uploads
the artefact, which is then consumed by `pnpm tauri build`.

## Test plan

- **Unit** — each router tested with `httpx.AsyncClient` against a
  mounted FastAPI app.
- **Integration** — full spawn test: launch the bundled sidecar
  binary as a subprocess, parse the handshake line, hit `/healthz`,
  shut it down via SIGTERM.
- **Security** — bind-address probe (assert no LAN listener), token
  rejection probe (assert 401 on missing/wrong token), parameter
  fuzzing on POST bodies (Pydantic validation rejects malformed
  inputs without panic).

## Open questions

- WebSocket vs Server-Sent Events for progress streaming ? WebSocket
  picked because it allows future bidirectional commands (cancel an
  in-flight operation, chunked uploads). Trade-off accepted: slightly
  more complex than SSE.
