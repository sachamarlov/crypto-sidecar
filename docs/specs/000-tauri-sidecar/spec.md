# 000 — Tauri sidecar (FastAPI)

- Status: draft
- Owner: Claude Opus 4.7 (implementation), @sachamarlov (review)
- Tracks: GUI extension (Tauri shell ↔ Python crypto engine bridge)

## Behaviour

The sidecar is a Python process spawned by the Tauri shell at
`guardiabox.exe` startup. It exposes the same operations as the CLI
but over an HTTP interface bound to `127.0.0.1` only. The Tauri shell
acts as the **only** legitimate client of the sidecar : authenticated
via a per-launch session token.

The sidecar is bundled as a single executable by PyInstaller
(`scripts/build_sidecar.py`) and shipped alongside the Tauri shell via
`tauri.conf.json > bundle.externalBin` (the externalBin entry is added
back in this spec's PR ; see `src-tauri/README.md`).

## Acceptance criteria (Gherkin)

```gherkin
Scenario: Sidecar startup contract
  When `guardiabox-sidecar` is spawned
  Then it binds to a free TCP port on 127.0.0.1
  And it generates a 32-byte session token via secrets.token_urlsafe
  And it prints exactly one stdout line: "GUARDIABOX_SIDECAR=<port> <token>\n"
  And subsequent stdout lines are JSON log records
  And the process stays alive until killed or until SIGTERM is received

Scenario: Authentication contract
  When a request is made to any /api/v1/* endpoint without the session token
  Then the response is HTTP 401 with body {"error": "missing or invalid token"}
  And no work is performed

Scenario: Session token transport
  Given a valid session token
  When the request includes header "X-GuardiaBox-Token: <token>"
  Then the request is dispatched to the underlying handler

Scenario: External callers cannot reach the sidecar
  Given the sidecar is running on 127.0.0.1:<port>
  When an external host attempts to connect to the LAN address of the machine
  Then the connection is refused (the listener is bound to 127.0.0.1 only)

Scenario: Encrypt flow over HTTP
  Given an authenticated request
  When I POST /api/v1/encrypt with body
       {"path": "/abs/foo.pdf", "password": "<base64>", "kdf": "argon2id"}
  Then the sidecar performs the encrypt operation via guardiabox.core
  And returns 200 with body
       {"output": "/abs/foo.pdf.crypt", "size_bytes": 1234567, "elapsed_ms": 432}

Scenario: Long operations stream progress over WebSocket
  Given an active session
  When I open WS /api/v1/stream
  Then I receive JSON frames {"event": "progress", "operation_id": "...", "percent": N}
  And one final frame {"event": "done", "operation_id": "...", "result": {...}}

Scenario: Graceful shutdown
  When the sidecar receives SIGTERM (or its parent process exits)
  Then in-flight operations are allowed up to 5 seconds to finish
  And the audit log records "sidecar.shutdown"
  And the process exits with code 0
```

## Out of scope (future)

- TLS termination (unnecessary on loopback ; revisit if we ever bind
  to LAN).
- OPAQUE / SRP authenticated key exchange (unnecessary while the
  sidecar is single-tenant ; revisit for the optional sync server).
- OpenAPI client generation for the React frontend (planned in spec
  `000-tauri-frontend`).
