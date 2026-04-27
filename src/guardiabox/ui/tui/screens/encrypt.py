"""Encrypt screen — ModalScreen wrapping core.operations.encrypt_file.

The screen reads a file path + password + KDF choice, then runs the
encrypt operation in a worker so the UI stays responsive. On success
a green toast notifies the user; on failure a red toast surfaces the
domain error message.

The path entry is a plain :class:`Input` for now — Textual ships a
:class:`DirectoryTree` widget but the spec MVP keeps the surface
minimal. A future iteration may add a file picker.
"""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Select, Static

from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.core.operations import encrypt_file
from guardiabox.ui.tui.widgets.password_field import PasswordField
from guardiabox.ui.tui.widgets.toast import Toast, ToastVariant


class EncryptScreen(ModalScreen[None]):
    """Modal: encrypt a file with a password (PBKDF2 default, Argon2id opt-in)."""

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold]Chiffrer un fichier[/bold]", id="modal-title"),
            Input(
                placeholder="Chemin du fichier à chiffrer",
                id="encrypt-path",
            ),
            PasswordField(widget_id="encrypt-password", placeholder="Mot de passe"),
            Select(
                [("PBKDF2-HMAC-SHA256", "pbkdf2"), ("Argon2id", "argon2id")],
                value="pbkdf2",
                id="encrypt-kdf",
            ),
            Horizontal(
                Button("Chiffrer", variant="primary", id="encrypt-submit"),
                Button("Annuler", id="encrypt-cancel"),
                id="button-row",
            ),
            id="modal-frame",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "encrypt-cancel":
            self.app.pop_screen()
            return
        if event.button.id == "encrypt-submit":
            self._submit()

    def _submit(self) -> None:
        path_input = self.query_one("#encrypt-path", Input).value.strip()
        if not path_input:
            Toast.show(self, "Chemin de fichier requis.", variant=ToastVariant.WARNING)
            return
        password = self.query_one("#encrypt-password", PasswordField).password
        if not password:
            Toast.show(self, "Mot de passe requis.", variant=ToastVariant.WARNING)
            return
        kdf_select = self.query_one("#encrypt-kdf", Select)
        kdf_value = kdf_select.value
        kdf = Argon2idKdf() if kdf_value == "argon2id" else Pbkdf2Kdf()
        source = Path(path_input)
        if not source.is_file():
            Toast.show(
                self,
                f"Fichier introuvable : {source}",
                variant=ToastVariant.ERROR,
            )
            return
        # Run the blocking encrypt in a worker so the UI keeps refreshing.
        self.app.run_worker(
            lambda: self._encrypt_worker(source=source, password=password, kdf=kdf),
            exclusive=True,
            thread=True,
        )

    def _encrypt_worker(
        self,
        *,
        source: Path,
        password: str,
        kdf: Pbkdf2Kdf | Argon2idKdf,
    ) -> None:
        """Sync worker: KDF + AES-GCM streaming + atomic write."""
        try:
            result_path = encrypt_file(source, password, root=source.parent, kdf=kdf)
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
            f"Chiffré : {result_path}",
            variant=ToastVariant.SUCCESS,
        )
        self.app.call_from_thread(self.app.pop_screen)
