"""Decrypt screen — ModalScreen wrapping core.operations.decrypt_file.

Anti-oracle ordering enforced by :func:`core.operations.decrypt_file`
itself: the wrong-password and tampered-ciphertext failures collapse
into the same :class:`DecryptionError`, surfaced uniformly via the
toast. The screen does not log the exception class to keep the
contract.
"""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from guardiabox.core.exceptions import DecryptionError, IntegrityError
from guardiabox.core.operations import decrypt_file
from guardiabox.ui.cli.io import ANTI_ORACLE_MESSAGE
from guardiabox.ui.tui.widgets.password_field import PasswordField
from guardiabox.ui.tui.widgets.toast import Toast, ToastVariant


class DecryptScreen(ModalScreen[None]):
    """Modal: decrypt a .crypt file back to its plaintext."""

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold]Déchiffrer un fichier[/bold]", id="modal-title"),
            Input(
                placeholder="Chemin du fichier .crypt",
                id="decrypt-path",
            ),
            Input(
                placeholder="Destination (laisser vide pour <fichier>.decrypt)",
                id="decrypt-output",
            ),
            PasswordField(
                widget_id="decrypt-password",
                placeholder="Mot de passe",
                live_strength=False,
            ),
            Horizontal(
                Button("Déchiffrer", variant="primary", id="decrypt-submit"),
                Button("Annuler", id="decrypt-cancel"),
                id="button-row",
            ),
            id="modal-frame",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "decrypt-cancel":
            self.app.pop_screen()
            return
        if event.button.id == "decrypt-submit":
            self._submit()

    def _submit(self) -> None:
        path_value = self.query_one("#decrypt-path", Input).value.strip()
        output_value = self.query_one("#decrypt-output", Input).value.strip()
        password = self.query_one("#decrypt-password", PasswordField).password
        if not path_value:
            Toast.show(self, "Chemin de fichier requis.", variant=ToastVariant.WARNING)
            return
        if not password:
            Toast.show(self, "Mot de passe requis.", variant=ToastVariant.WARNING)
            return
        source = Path(path_value)
        if not source.is_file():
            Toast.show(
                self,
                f"Fichier introuvable : {source}",
                variant=ToastVariant.ERROR,
            )
            return
        dest = Path(output_value) if output_value else None
        self.app.run_worker(
            lambda: self._decrypt_worker(source=source, password=password, dest=dest),
            exclusive=True,
            thread=True,
        )

    def _decrypt_worker(
        self,
        *,
        source: Path,
        password: str,
        dest: Path | None,
    ) -> None:
        """Sync worker: read header, KDF, AES-GCM verify + decrypt."""
        try:
            result_path = decrypt_file(source, password, root=source.parent, dest=dest)
        except (DecryptionError, IntegrityError):
            # Anti-oracle: do NOT distinguish wrong-password from
            # tampered-ciphertext. Same generic toast.
            self.app.call_from_thread(
                Toast.show,
                self.app,
                ANTI_ORACLE_MESSAGE,
                variant=ToastVariant.ERROR,
            )
            return
        except Exception as exc:
            self.app.call_from_thread(
                Toast.show,
                self.app,
                f"Échec : {type(exc).__name__} -- {exc}",
                variant=ToastVariant.ERROR,
            )
            return
        self.app.call_from_thread(
            Toast.show,
            self.app,
            f"Déchiffré : {result_path}",
            variant=ToastVariant.SUCCESS,
        )
        self.app.call_from_thread(self.app.pop_screen)
