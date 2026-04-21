# `src-tauri/` — Tauri 2 Rust shell

Hosts the WebView2 window, mediates IPC between the React frontend and the
Python sidecar, and is the entry point bundled into `guardiabox.exe` by
`pnpm tauri build`.

## Configuration discipline

`tauri.conf.json` is parsed by `tauri-build::build()` (called from `build.rs`)
with **strict schema validation**: any unknown field aborts `cargo check`,
`cargo clippy`, and any subsequent build.

Two consequences worth remembering:

1. **No JSON-style comments** are tolerated. JSON natively forbids comments
   and Tauri does not allow JSON5/JSONC extensions. The "fake key for
   comment" pattern (e.g. `"_my_note": "..."`) **does not work** and triggers
   `unknown field`.

2. **`bundle.externalBin` is currently absent on purpose.** The Python
   sidecar binary it would point at (`binaries/guardiabox-sidecar`) is not
   yet produced by `scripts/build_sidecar.py` — declaring an external
   binary that does not exist breaks the bundle phase.

   **When the sidecar PyInstaller pipeline lands** (see
   `docs/specs/000-tauri-sidecar/`), the same PR must restore:

   ```jsonc
   "bundle": {
     ...
     "externalBin": ["binaries/guardiabox-sidecar"],
     ...
   }
   ```

   and ensure `src-tauri/binaries/guardiabox-sidecar-<TARGET_TRIPLE>(.exe)`
   exists for every CI matrix entry that builds the bundle.

## Capabilities

`capabilities/default.json` lists every permission the WebView is allowed
to invoke, **explicitly and individually** — no `<plugin>:default` blanket
fallbacks. Adding a permission means a feature spec needs it; removing one
means the feature using it has been deprecated.

The currently-allowed `core:*:default` identifiers are the nine documented
in <https://v2.tauri.app/reference/acl/core-permissions/>:

```
core:default
core:app:default
core:event:default
core:image:default
core:menu:default
core:path:default
core:resources:default
core:tray:default
core:webview:default
core:window:default
```

## Local commands

```bash
# Format check (does not compile)
cargo fmt --all -- --check

# Lint (must compile, runs `tauri-build` build script)
cargo clippy --all-targets --all-features -- -D warnings

# Generate Cargo.lock without downloading deps' content
cargo generate-lockfile

# Full Tauri development cycle (frontend HMR + Rust shell)
pnpm --dir ../frontend tauri dev
```
