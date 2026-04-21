# 000 — CLI — technical plan

## Touched modules

- `guardiabox.ui.cli.main` — Typer `app` instance, root callback,
  `--version` flag.
- `guardiabox.ui.cli.commands.{init,encrypt,decrypt,share,accept,
secure_delete,user,history,sync,config,doctor,menu}` — one Typer
  command per module, registered on `app`.
- `guardiabox.ui.cli.io` — shared helpers: password prompts (no echo),
  progress bars (Rich), JSON serialisers, exit-code mappers.

## Architecture

```
guardiabox.ui.cli.main:app
    │
    ├── @app.callback(invoke_without_command=True)
    │     -> handle --version, dispatch to "menu" if no subcommand
    │
    ├── encrypt    (commands.encrypt)
    ├── decrypt    (commands.decrypt)
    ├── share      (commands.share)
    ├── accept     (commands.accept)
    ├── secure-delete (commands.secure_delete)
    ├── user       (commands.user, sub-Typer with create/list/delete/...)
    ├── history    (commands.history)
    ├── sync       (commands.sync, sub-Typer with push/pull/status)
    ├── config     (commands.config, get/set/list)
    ├── doctor     (commands.doctor)
    └── menu       (commands.menu, interactive REPL)
```

Each command imports `core` operations directly (no HTTP roundtrip to
the sidecar — CLI is a primary adapter alongside the Tauri sidecar,
not a client of it).

## Exit-code mapping

| Code | Meaning                                 |
| ---- | --------------------------------------- |
| 0    | success                                 |
| 1    | generic / unrecoverable error           |
| 2    | wrong password / decryption failed      |
| 3    | file not found / path-traversal refused |
| 64   | usage error (EX_USAGE)                  |
| 65   | data error (EX_DATAERR)                 |
| 78   | configuration error (EX_CONFIG)         |
| 130  | interrupted by user (SIGINT)            |

`commands.io.exit_for(exception)` centralises the mapping.

## Test plan

- **Unit** — each command's Click context invocation via
  `typer.testing.CliRunner` (offline, no subprocess overhead).
- **E2E** — `subprocess.run(["uv", "run", "guardiabox", ...])` for the
  installed-script path ; smoke test of `--help` for every command.
- **Snapshot** — `--json` outputs are validated against frozen schemas
  (Pydantic models in `guardiabox.ui.cli.io.schemas`).

## Open questions

- Locale of error messages : English or French ? Current proposal:
  English for the messages (technical audience), French for the
  documented help texts (`--help`) once we add i18n. Defer to spec
  `000-i18n` post-MVP.
