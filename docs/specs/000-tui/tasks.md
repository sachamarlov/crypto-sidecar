# 000 — TUI — task breakdown

- [ ] **T-000tui.01** — `app.py` `GuardiaBoxApp` skeleton + Header /
      Body / Footer composition + dark theme.
- [ ] **T-000tui.02** — `widgets.user_sidebar.UserSidebar` (lists users
      via UserRepository, emits `UserSelected` message).
- [ ] **T-000tui.03** — `widgets.vault_table.VaultTable` (DataTable
      bound to VaultItemRepository, supports search, sort, multi-select).
- [ ] **T-000tui.04** — `widgets.password_field.PasswordField` (no-echo
      input + zxcvbn live strength bar).
- [ ] **T-000tui.05** — `widgets.toast.Toast` (positioned top-right,
      auto-dismiss after configurable timeout, info/success/warning/error
      variants).
- [ ] **T-000tui.06** — `screens.dashboard.DashboardScreen` (default
      screen, action bar, key bindings e/d/s/h).
- [ ] **T-000tui.07** — `screens.encrypt.EncryptScreen` (file picker +
      password + KDF choice + progress).
- [ ] **T-000tui.08** — `screens.decrypt.DecryptScreen` (file picker +
      password + output path + progress + error handling).
- [ ] **T-000tui.09** — `screens.share.ShareScreen` (recipient picker
      via UserRepository + permissions + expiry + summary).
- [ ] **T-000tui.10** — `screens.history.HistoryScreen` (AuditRepository
      reverse-chrono with filter widgets).
- [ ] **T-000tui.11** — `screens.settings.SettingsScreen` (KDF
      selection, auto-lock minutes, theme, BIP-39 backup export).
- [ ] **T-000tui.12** — Snapshot tests for every screen
      (`pytest-textual-snapshot`).
- [ ] **T-000tui.13** — Reduced-motion path (probe `os.environ['TERM']`
      and disable Textual animations when warranted).

Definition of Done: every acceptance scenario passes ; snapshot tests
green ; coverage ≥ 80 % on `ui/tui/` (lower than the core target
because Textual rendering is asserted via snapshots not branches) ; no
direct imports from `ui/cli/`, `ui/tauri/`, or networking modules.
