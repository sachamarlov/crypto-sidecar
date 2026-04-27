"""Settings screen — read-only summary of the active configuration.

Mirrors the CLI ``guardiabox config list`` output (Phase E). Persistent
``set`` operations are deferred post-MVP at the CLI level too -- the
TUI shows the same flat dump so power users can understand which env
vars are in effect without leaving the terminal app.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from guardiabox.config import get_settings


def _flatten(node: Any, *, parent: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    if not isinstance(node, dict):
        return {parent: node}
    for key, value in node.items():
        full = f"{parent}.{key}" if parent else key
        if isinstance(value, dict):
            flat.update(_flatten(value, parent=full))
        else:
            flat[full] = value
    return flat


class SettingsScreen(ModalScreen[None]):
    """Modal: show the active settings, read-only."""

    def compose(self) -> ComposeResult:
        flat = _flatten(get_settings().model_dump())
        width = max((len(k) for k in flat), default=0) + 2
        rows = [f"{k.ljust(width)}{flat[k]}" for k in sorted(flat)]
        body = "\n".join(rows) if rows else "(empty)"
        yield Container(
            Static("[bold]Configuration courante[/bold]", id="modal-title"),
            Static(""),
            Static(body),
            Static(""),
            Static(
                "[dim]Persistent set is deferred post-MVP -- override via "
                "GUARDIABOX_<KEY> env vars or .env in cwd.[/dim]"
            ),
            Horizontal(
                Button("Fermer", id="settings-close"),
                id="button-row",
            ),
            id="modal-frame",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "settings-close":
            self.app.pop_screen()
