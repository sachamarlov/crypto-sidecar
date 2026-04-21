# 000 — TUI — technical plan

## Touched modules

- `guardiabox.ui.tui.app` — `GuardiaBoxApp(App[None])`, top-level
  composition (Header, Sidebar, MainPanel, Footer).
- `guardiabox.ui.tui.screens.{dashboard,encrypt,decrypt,share,history,
settings}` — one Textual `Screen` per major view.
- `guardiabox.ui.tui.widgets.{vault_table,user_sidebar,toast,
password_field}` — reusable Textual widgets.
- `guardiabox.ui.tui.bindings` — global key bindings declared once and
  documented in the Footer.
- `guardiabox.ui.tui.main` — entry point `run()` registered in
  `[project.scripts]`.

## Architecture

```
GuardiaBoxApp (App[None])
    Header  (current user, time, lock indicator)
    Body
        UserSidebar  (active user + switcher)
        ContentArea  (Screen.swap on navigation)
            DashboardScreen  (default)
                VaultTable   (DataTable widget)
                ActionBar    (encrypt / decrypt / share buttons)
            EncryptScreen    (modal-style)
            DecryptScreen    (modal-style)
            ShareScreen      (modal-style)
            HistoryScreen
            SettingsScreen
    Footer  (key bindings, status messages)
```

Screens push/pop on the app stack. Long-running operations (KDF,
streaming encrypt/decrypt) run in `App.run_worker(...)` so the UI
stays responsive ; progress is reported back via posted messages.

## Test plan

- **Unit** — each widget rendered via Textual's `App.run_test()`
  context, assertions on the DOM snapshot.
- **Integration** — full app lifecycle: launch → unlock → encrypt →
  decrypt → quit, asserting on screen transitions and final DB state.
- **Snapshot** — `pytest-textual-snapshot` plugin to lock the rendered
  output of each screen against an SVG reference.

## Open questions

- Use the new Textual 0.89 `command palette` widget for the global
  `:` action launcher ? Decision deferred to first implementation
  iteration ; if it doesn't compose cleanly with our screen stack we
  fall back to plain key bindings.
