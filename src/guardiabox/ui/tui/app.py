"""Textual application — Phase F entry point.

Architecture mirrors the desktop GUI's information architecture (sidebar
+ vault table + action bar) within terminal constraints. Long-running
ops (KDF, streaming encrypt/decrypt) run via :meth:`App.run_worker` so
the UI stays responsive at all times.

Design notes
------------

* **No imports from** :mod:`guardiabox.ui.cli` or
  :mod:`guardiabox.ui.tauri` — the TUI is a sibling adapter, not a
  client of another UI layer. It calls :mod:`guardiabox.core.operations`
  and :mod:`guardiabox.persistence` directly, like the CLI does.
* **Screens are modal-stack** — :class:`DashboardScreen` is the default
  screen. Action keys (e/d/s/h/c) push the relevant
  :class:`textual.screen.ModalScreen` on top.
* **Reduced-motion mode** — the entry point in :mod:`main` probes
  ``TERM=dumb`` and disables animations before instantiating the app.
"""

from __future__ import annotations

from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.widgets import Footer, Header

from guardiabox.ui.tui.screens.dashboard import DashboardScreen


class GuardiaBoxApp(App[None]):
    """Top-level Textual application for GuardiaBox.

    The default screen is :class:`DashboardScreen`. Global bindings:

    * ``q`` -- quit
    * ``e`` -- push EncryptScreen
    * ``d`` -- push DecryptScreen
    * ``s`` -- push ShareScreen
    * ``h`` -- push HistoryScreen
    * ``c`` -- push SettingsScreen (config)
    * ``ctrl+l`` -- toggle dark / light theme
    """

    TITLE = "GuardiaBox"
    SUB_TITLE = "Local secure vault"

    CSS_PATH = "app.tcss"

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("ctrl+l", "toggle_dark", "Theme"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Footer()

    def on_mount(self) -> None:
        """Push the default screen and wire reduced-motion when applicable."""
        self.push_screen(DashboardScreen())

    def action_toggle_dark(self) -> None:
        """Toggle between the two bundled themes."""
        self.theme = "textual-light" if self.theme == "textual-dark" else "textual-dark"
