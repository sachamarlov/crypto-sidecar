"""History screen — read the audit log in reverse-chronological order.

Reads the local vault DB (admin password required) and renders the
last 200 entries in a :class:`DataTable`. Filters are not yet wired in
the TUI surface — for advanced filters the user falls back to the CLI
``guardiabox history --user X --action Y --format json``. Documented
honestly as a follow-up.
"""

from __future__ import annotations

import asyncio

from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Static

from guardiabox.persistence.bootstrap import vault_paths
from guardiabox.persistence.database import create_engine, session_scope
from guardiabox.persistence.repositories import AuditRepository, UserRepository
from guardiabox.security.vault_admin import (
    VaultAdminConfigMissingError,
    derive_admin_key,
    read_admin_config,
)
from guardiabox.ui.tui.widgets.password_field import PasswordField
from guardiabox.ui.tui.widgets.toast import Toast, ToastVariant


class HistoryScreen(ModalScreen[None]):
    """Modal: render the audit log in a DataTable.

    Two-step flow: prompt for the admin password (so the row's
    encrypted columns can be decrypted), then load + display the rows.
    """

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold]Journal d'audit[/bold]", id="modal-title"),
            PasswordField(
                widget_id="history-password",
                placeholder="Mot de passe administrateur",
                live_strength=False,
            ),
            Button("Charger", variant="primary", id="history-load"),
            DataTable(id="history-table"),
            Button("Fermer", id="history-close"),
            id="modal-frame",
        )

    def on_mount(self) -> None:
        table = self.query_one("#history-table", DataTable)
        table.add_columns("seq", "timestamp", "actor", "action", "target")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "history-close":
            self.app.pop_screen()
            return
        if event.button.id == "history-load":
            password = self.query_one("#history-password", PasswordField).password
            if not password:
                Toast.show(self, "Mot de passe requis.", variant=ToastVariant.WARNING)
                return
            self.app.run_worker(
                lambda: self._load_worker(password=password),
                exclusive=True,
                thread=True,
            )

    def _load_worker(self, *, password: str) -> None:
        """Sync worker that runs the async DB read and posts back to the UI."""
        try:
            rows = asyncio.run(_fetch_rows(password=password))
        except VaultAdminConfigMissingError:
            self.app.call_from_thread(
                Toast.show,
                self.app,
                "Coffre non initialisé -- lancer `guardiabox init`.",
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

        def _populate() -> None:
            table = self.query_one("#history-table", DataTable)
            table.clear()
            for row in rows:
                table.add_row(*row)

        self.app.call_from_thread(_populate)
        self.app.call_from_thread(
            Toast.show,
            self.app,
            f"{len(rows)} entrées chargées.",
            variant=ToastVariant.SUCCESS,
        )


async def _fetch_rows(*, password: str) -> list[tuple[str, ...]]:
    """Open the vault, decrypt every audit row, return tuples for the DataTable."""
    from guardiabox.config import get_settings

    paths = vault_paths(get_settings().data_dir)
    config = read_admin_config(paths.admin_config)
    admin_key = derive_admin_key(config, password)

    engine = create_engine(f"sqlite+aiosqlite:///{paths.db}")
    try:
        async with session_scope(engine) as session:
            audit_repo = AuditRepository(session, admin_key)
            user_repo = UserRepository(session, admin_key)
            entries = await audit_repo.list_filtered(limit=200)
            users = await user_repo.list_all()
            user_map = {u.id: user_repo.decrypt_username(u) for u in users}

            rendered: list[tuple[str, ...]] = []
            for entry in entries:
                actor = (
                    user_map.get(entry.actor_user_id, "<unknown>")
                    if entry.actor_user_id
                    else "<system>"
                )
                target = audit_repo.decrypt_target(entry) if entry.target_enc else ""
                rendered.append(
                    (
                        str(entry.sequence),
                        entry.timestamp.isoformat(timespec="seconds"),
                        actor,
                        entry.action,
                        target or "",
                    )
                )
            return rendered
    finally:
        await engine.dispose()
