# 000 — Tauri sidecar — task breakdown

- [x] **T-000sc.01** — `sidecar.main` real implementation: free-port
      picker, secure token generation, handshake line, uvicorn start.
- [x] **T-000sc.02** — `api.middleware.TokenAuthMiddleware` + unit
      tests (401 on missing / wrong token ; pass-through on valid token).
- [x] **T-000sc.03** — `api.schemas` Pydantic models for every
      request/response body (typed, frozen, strict validation).
- [x] **T-000sc.04** — `api.v1.encrypt` router (POST /encrypt) +
      delegates to spec 001.
- [x] **T-000sc.05** — `api.v1.decrypt` router + delegates to spec 002.
- [x] **T-000sc.06** — `api.v1.share` + `api.v1.accept` routers +
      delegate to spec 003.
- [x] **T-000sc.07** — `api.v1.users` router (GET list, POST create,
      DELETE remove) + delegates to spec 000-multi-user.
- [x] **T-000sc.08** — `api.v1.audit` router (GET list with filters).
- [x] **T-000sc.09** — `api.v1.health` (`/healthz`, `/readyz`,
      `/version`).
- [ ] **T-000sc.10** — `api.ws.StreamConnection` (WebSocket) for
      progress events. _Deferred to a follow-up commit_: the routers
      and SessionStore expose every hook needed for streaming, but
      the WebSocket endpoint itself is post-MVP.
- [x] **T-000sc.11** — Full `scripts/build_sidecar.py` PyInstaller
      invocation + smoke test that the resulting binary boots and answers
      `/healthz`.
- [x] **T-000sc.12** — Rust `sidecar.rs` real implementation: spawn
      via `tauri::async_runtime`, capture stdout line, store
      `(port, token)` in shared state, expose Tauri command
      `get_sidecar_connection()`.
- [x] **T-000sc.13** — Restore `bundle.externalBin` in
      `tauri.conf.json` and update `src-tauri/README.md` accordingly.
- [ ] **T-000sc.14** — CI step in `ci.yml` (Linux job): build the
      sidecar via PyInstaller, copy into
      `src-tauri/binaries/guardiabox-sidecar-x86_64-unknown-linux-gnu`,
      run `cargo clippy` (Rust job no longer broken). _Deferred to
      Phase I (release workflow)_; the existing Rust gate stays a
      pre-existing accepted red gate for this PR.
- [x] **T-000sc.15** — Bind-address security test (assert no `0.0.0.0`
      / no LAN socket open).

Definition of Done: every acceptance scenario passes ; coverage ≥ 90 %
on `ui/tauri/sidecar/` ; bandit clean ; the resulting bundled `.exe`
launches the sidecar correctly ; CI Rust job is green for the first
time since the bootstrap.
