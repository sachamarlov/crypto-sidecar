"""Share screen — placeholder pointing to the CLI flow.

The full share flow ships in Phase D as a CLI command (``guardiabox
share`` + ``guardiabox accept``). Wrapping it inside the TUI requires
a recipient picker reading the vault DB + a fingerprint confirmation
dialog -- both are tractable but out of scope for the MVP TUI window.
The screen surfaces a clear pointer to the CLI so users always have a
working path.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class ShareScreen(ModalScreen[None]):
    """Modal: redirect users to the CLI ``guardiabox share`` flow."""

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold]Partage RSA hybride[/bold]", id="modal-title"),
            Static(""),
            Static(
                "Le partage entre utilisateurs locaux est livré via la CLI :",
            ),
            Static(""),
            Static("  [cyan]guardiabox share <fichier.crypt> --from alice --to bob[/cyan]"),
            Static("  [cyan]guardiabox accept <jeton.gbox-share> --from alice --as bob[/cyan]"),
            Static(""),
            Static(
                "L'enveloppe TUI sera ajoutée post-MVP (recipient picker + "
                "confirmation d'empreinte SHA-256)."
            ),
            Horizontal(
                Button("OK", id="share-close"),
                id="button-row",
            ),
            id="modal-frame",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "share-close":
            self.app.pop_screen()
