# 000 — CLI — task breakdown

- [x] **T-000cli.01** — `commands.io` (`ExitCode`, `exit_for`,
      `read_password`) + `_session.py` for vault-aware commands.
- [x] **T-000cli.02** — `commands.encrypt` (spec 001) + tests.
- [x] **T-000cli.03** — `commands.decrypt` (spec 002) + anti-oracle.
- [x] **T-000cli.04** — `commands.share` + `commands.accept` (spec 003,
      Phase D).
- [x] **T-000cli.05** — `commands.secure_delete` (spec 004 Phase B1 +
      `--method crypto-erase` Phase B2).
- [x] **T-000cli.06** — `commands.user` sub-Typer (create/list/delete/show).
      `export-pubkey` / `import-pubkey` were folded into Phase D
      (the share flow stores pubkeys in the DB ; explicit export/import
      is a roadmap item).
- [x] **T-000cli.07** — `commands.history` with filters + `--format`.
- [x] **T-000cli.08** — `commands.config` sub-Typer (`list` + `get`).
      `set` deferred post-MVP — the message redirects users to env vars
      / `.env` (pydantic-settings has no native CLI persistence layer).
- [x] **T-000cli.09** — `commands.doctor` (vault paths + SQLCipher
      report + `--verify-audit` + `--report-ssd` + `--format`).
- [x] **T-000cli.10** — `commands.menu` (Fix-1.G — CDC F-7 mandatoire).
- [x] **T-000cli.11** — `commands.init` (Phase C-2 bootstrap).
- [x] **T-000cli.12** — `--quiet` / `--verbose` global flags on the
      root callback. Mutex enforced. `--verbose` = structlog DEBUG ;
      `--quiet` = ERROR + `GUARDIABOX_QUIET=1` env var (consumable by
      individual commands as a follow-up).
- [x] **T-000cli.13** — `--format json|table` on `user list`,
      `user show`, `doctor` (already on `history` since Phase C-2).

Definition of Done: every acceptance scenario from `spec.md` passes ;
coverage ≥ 90 % on `ui/cli/` ; smoke `--help` test for every command in
CI ; no command imports anything from `ui/tauri` or other sibling
adapters (hexagonal discipline).
