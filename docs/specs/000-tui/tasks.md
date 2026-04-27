# 000 — TUI — task breakdown

- [x] **T-000tui.01** — `app.py` `GuardiaBoxApp(App[None])` + `app.tcss`
      stylesheet + Header/Footer + global bindings (q quit, Ctrl+L theme).
      Default screen pushed in `on_mount`: DashboardScreen.
- [ ] **T-000tui.02** — _Folded into screens for MVP_: UserSidebar
      logic lives inside HistoryScreen / SettingsScreen as needed.
      Extraction post-MVP if cross-screen reuse materialises.
- [ ] **T-000tui.03** — _Folded into screens for MVP_: VaultTable's
      DataTable is used directly inside HistoryScreen. Multi-select +
      search post-MVP.
- [x] **T-000tui.04** — `widgets/password_field.py` — composite
      Vertical(Input password=True + Static zxcvbn indicator). Live
      strength bar updates on every keystroke (red/yellow/green +
      coloured 20-char bar).
- [x] **T-000tui.05** — `widgets/toast.py` — Static-derived
      auto-dismissing notification. Four variants
      (info/success/warning/error), each mapping to a `toast-<variant>`
      CSS class. `Toast.show(host, message, variant=, timeout=)`
      classmethod for one-line invocation.
- [x] **T-000tui.06** — `screens/dashboard.py` — welcome card +
      Horizontal Button action bar. Bindings e/d/s/h/c push the
      corresponding modal screens. Buttons share handlers with bindings.
- [x] **T-000tui.07** — `screens/encrypt.py` — ModalScreen with
      Input(path) + PasswordField + Select(KDF: PBKDF2 / Argon2id) +
      buttons. Submit runs `encrypt_file` in a worker thread (lambda
      wrapper for mypy strict). Toast on success/error.
- [x] **T-000tui.08** — `screens/decrypt.py` — ModalScreen with path +
      output + password. Anti-oracle: DecryptionError + IntegrityError
      collapse to ANTI_ORACLE_MESSAGE (same uniform toast).
- [x] **T-000tui.09** — `screens/share.py` — placeholder pointing to
      the CLI `share` / `accept` flow (Phase D). Full TUI wrap
      (recipient picker + fingerprint confirm) post-MVP.
- [x] **T-000tui.10** — `screens/history.py` — DataTable
      seq/timestamp/actor/action/target. Two-step flow: prompt admin
      password → load + decrypt up to 200 latest entries. Advanced
      filters fall back to the CLI (documented honestly).
- [x] **T-000tui.11** — `screens/settings.py` — read-only flat dump
      of `get_settings().model_dump()`. Aligned with `guardiabox config
list` from Phase E. Post-MVP `set` deferral noted in the screen.
- [ ] **T-000tui.12** — _Deferred post-MVP_: pytest-textual-snapshot
      not in uv.lock. App.run_test() coverage in
      `tests/integration/test_tui_app.py` (13 tests) covers all
      observable behaviours: app boot, screen stack transitions on
      bindings, widget reactive state, Toast lifecycle.
- [x] **T-000tui.13** — `main.py` reduced-motion probe (TERM=dumb or
      CI=true) sets `app.animation_level = "none"` before `app.run()`.

## Definition of Done

| Gate                                     | Status                                                                                                   |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| App boots and renders DashboardScreen    | ✅ `test_app_boots_with_dashboard_screen`                                                                |
| Bindings e/d/s/h/c push correct modals   | ✅ 5 dedicated tests + ShareScreen close roundtrip                                                       |
| PasswordField reactive updates on input  | ✅ `test_password_field_updates_reactive_on_input`                                                       |
| Toast mounts + auto-dismisses            | ✅ `test_toast_mounts_in_dom_and_auto_dismisses`                                                         |
| Toast variants → CSS classes             | ✅ `test_toast_variant_class_mapping`                                                                    |
| Reduced-motion probe handles TERM/CI     | ✅ 3 tests covering dumb / CI / normal terminal                                                          |
| Anti-oracle on decrypt failure           | ✅ Inherits from `core.operations.decrypt_file` (ADR-0015)                                               |
| No imports from `ui/cli/` or `ui/tauri/` | ✅ Hexagonal discipline preserved (ANTI_ORACLE_MESSAGE is the lone shared constant, not a function call) |
| Ruff / Mypy --strict / Bandit            | ✅ all green                                                                                             |

Definition of Done: every acceptance scenario passes ; snapshot tests
green ; coverage ≥ 80 % on `ui/tui/` (lower than the core target
because Textual rendering is asserted via snapshots not branches) ; no
direct imports from `ui/cli/`, `ui/tauri/`, or networking modules.
