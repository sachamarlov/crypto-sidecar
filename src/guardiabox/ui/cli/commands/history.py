"""``guardiabox history`` — read the audit log.

Unlocks the vault with the admin password (same surface as the
other Phase C-2 commands), then streams the matching rows in
reverse-chronological order.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path

import typer

from guardiabox.persistence.repositories import AuditRepository, UserRepository
from guardiabox.ui.cli._session import open_vault_session
from guardiabox.ui.cli.io import exit_for
from guardiabox.ui.cli.main import app


class OutputFormat(StrEnum):
    """Rendering for the audit entries returned by ``history``."""

    TABLE = "table"
    JSON = "json"


@dataclass(frozen=True, slots=True)
class _RenderedEntry:
    sequence: int
    timestamp: datetime
    actor_username: str | None
    action: str
    target: str | None


@app.command("history")
def history_command(  # noqa: PLR0917 -- Typer commands expose one param per flag
    limit: int = typer.Option(50, "--limit", min=1, max=10_000),
    user: str | None = typer.Option(
        None,
        "--user",
        help="Restreindre aux entrées créées par cet utilisateur.",
    ),
    action: str | None = typer.Option(
        None,
        "--action",
        help="Restreindre à une action précise (ex. file.encrypt).",
    ),
    output: OutputFormat = typer.Option(
        OutputFormat.TABLE,
        "--format",
        case_sensitive=False,
        help="Format de sortie.",
    ),
    data_dir: Path | None = typer.Option(None, "--data-dir", show_default=False),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire le mot de passe administrateur depuis stdin.",
    ),
) -> None:
    """Lire les entrées du journal d'audit (tri décroissant par sequence)."""
    try:
        entries = asyncio.run(
            _history_flow(
                data_dir=data_dir,
                limit=limit,
                user=user,
                action=action,
                password_stdin=password_stdin,
            )
        )
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    if output is OutputFormat.JSON:
        import json as _json

        typer.echo(
            _json.dumps(
                [
                    {
                        "sequence": e.sequence,
                        "timestamp": e.timestamp.isoformat(),
                        "actor_username": e.actor_username,
                        "action": e.action,
                        "target": e.target,
                    }
                    for e in entries
                ],
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    if not entries:
        typer.echo("(journal vide)")
        return
    header = f"{'seq':>5}  {'timestamp':<32}  {'actor':<18}  action                target"
    typer.echo(header)
    typer.echo("-" * len(header))
    for e in entries:
        actor = e.actor_username or "—"
        target = e.target or ""
        typer.echo(
            f"{e.sequence:>5}  {e.timestamp.isoformat():<32}  {actor:<18}  {e.action:<20}  {target}"
        )


async def _history_flow(
    *,
    data_dir: Path | None,
    limit: int,
    user: str | None,
    action: str | None,
    password_stdin: bool,
) -> list[_RenderedEntry]:
    async with open_vault_session(data_dir, password_stdin=password_stdin) as (
        vault,
        session,
        _engine,
    ):
        user_repo = UserRepository(session, vault.admin_key)
        audit_repo = AuditRepository(session, vault.admin_key)

        actor_id: str | None = None
        if user is not None:
            matched = await user_repo.get_by_username(user)
            if matched is None:
                # No such user -> empty result rather than a hard error.
                return []
            actor_id = matched.id

        rows = await audit_repo.list_filtered(
            actor_user_id=actor_id,
            action=action,
            limit=limit,
        )

        # Pre-load every distinct actor id in one batch so we can attach
        # the plaintext username without issuing an N+1 sequence of
        # lookups. Actors may have been deleted (SET NULL on cascade);
        # those rows show up with actor_username = None.
        actor_map: dict[str, str] = {}
        distinct_ids = {r.actor_user_id for r in rows if r.actor_user_id is not None}
        for uid in distinct_ids:
            found = await user_repo.list_all()
            # Cheap linear scan -- ``list_all`` is already cached per
            # vault session and the number of local users stays low.
            for u in found:
                if u.id == uid:
                    actor_map[uid] = user_repo.decrypt_username(u)
                    break

        return [
            _RenderedEntry(
                sequence=r.sequence,
                timestamp=r.timestamp,
                actor_username=actor_map.get(r.actor_user_id or ""),
                action=r.action,
                target=audit_repo.decrypt_target(r),
            )
            for r in rows
        ]
