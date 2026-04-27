"""Dashboard screen — the default view of the GuardiaBox TUI.

Mirrors the desktop GUI layout: a welcome banner + an action bar with
the four most-frequent operations. Each button pushes its modal screen
on top of the dashboard. Key bindings duplicate the buttons for keyboard
users.
"""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Static


class DashboardScreen(Screen[None]):
    """Default screen: welcome card + action bar.

    Bindings are duplicated on the action bar buttons so both keyboard
    and pointer users share the same affordances.
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("e", "open_encrypt", "Encrypt"),
        Binding("d", "open_decrypt", "Decrypt"),
        Binding("s", "open_share", "Share"),
        Binding("h", "open_history", "History"),
        Binding("c", "open_settings", "Settings"),
    ]

    DEFAULT_CSS = """
    #dashboard-card {
        align: center middle;
        height: 1fr;
        padding: 2 4;
    }
    #dashboard-card > Static {
        text-align: center;
    }
    #dashboard-title {
        text-style: bold;
        color: $accent;
        padding-bottom: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold]GuardiaBox[/bold]", id="dashboard-title"),
            Static("Coffre-fort numérique local — chiffrement, partage et stockage."),
            Static(""),
            Static("Choisir une action ci-dessous, ou utiliser une touche ([e]/[d]/[s]/[h]/[c])."),
            id="dashboard-card",
        )
        yield Horizontal(
            Button("Encrypt (e)", id="btn-encrypt", variant="primary"),
            Button("Decrypt (d)", id="btn-decrypt", variant="primary"),
            Button("Share (s)", id="btn-share"),
            Button("History (h)", id="btn-history"),
            Button("Settings (c)", id="btn-settings"),
            id="dashboard-actions",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Translate button presses to action invocations."""
        button_to_action = {
            "btn-encrypt": self.action_open_encrypt,
            "btn-decrypt": self.action_open_decrypt,
            "btn-share": self.action_open_share,
            "btn-history": self.action_open_history,
            "btn-settings": self.action_open_settings,
        }
        handler = button_to_action.get(event.button.id or "")
        if handler is not None:
            handler()

    def action_open_encrypt(self) -> None:
        from guardiabox.ui.tui.screens.encrypt import EncryptScreen

        self.app.push_screen(EncryptScreen())

    def action_open_decrypt(self) -> None:
        from guardiabox.ui.tui.screens.decrypt import DecryptScreen

        self.app.push_screen(DecryptScreen())

    def action_open_share(self) -> None:
        from guardiabox.ui.tui.screens.share import ShareScreen

        self.app.push_screen(ShareScreen())

    def action_open_history(self) -> None:
        from guardiabox.ui.tui.screens.history import HistoryScreen

        self.app.push_screen(HistoryScreen())

    def action_open_settings(self) -> None:
        from guardiabox.ui.tui.screens.settings import SettingsScreen

        self.app.push_screen(SettingsScreen())
