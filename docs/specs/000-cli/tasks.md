# 000 — CLI — task breakdown

- [ ] **T-000cli.01** — `commands.io` shared helpers (password prompt,
      Rich progress, JSON serialisers, exit-code mapper).
- [ ] **T-000cli.02** — `commands.encrypt` (delegates to spec 001
      implementation) + `CliRunner` test.
- [ ] **T-000cli.03** — `commands.decrypt` (delegates to spec 002).
- [ ] **T-000cli.04** — `commands.share` + `commands.accept`
      (delegates to spec 003).
- [ ] **T-000cli.05** — `commands.secure_delete` (delegates to spec 004).
- [ ] **T-000cli.06** — `commands.user` sub-Typer
      (create/list/delete/export-pubkey/import-pubkey, delegates to
      spec 000-multi-user).
- [ ] **T-000cli.07** — `commands.history` (delegates to AuditRepository).
- [ ] **T-000cli.08** — `commands.config` (get/set/list backed by
      pydantic-settings).
- [ ] **T-000cli.09** — `commands.doctor` (deps check + audit chain
      verify + SQLCipher backend report).
- [ ] **T-000cli.10** — `commands.menu` interactive REPL covering the
      CDC-mandated three options + extension shortcuts.
- [ ] **T-000cli.11** — `commands.init` (one-shot install: create vault
      data dir, create administrator keystore, install pre-commit hooks,
      print onboarding tips).
- [ ] **T-000cli.12** — `--quiet` / `--verbose` global flags wired into
      `commands.io`.
- [ ] **T-000cli.13** — `--json` global flag for read commands.

Definition of Done: every acceptance scenario from `spec.md` passes ;
coverage ≥ 90 % on `ui/cli/` ; smoke `--help` test for every command in
CI ; no command imports anything from `ui/tauri` or other sibling
adapters (hexagonal discipline).
