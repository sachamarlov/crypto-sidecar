"""``guardiabox doctor`` — diagnostics + audit-chain verification.

Reports the vault's state in plain French text and, with
``--verify-audit``, walks the entire audit log to check the hash
chain holds. Exits non-zero when any check fails so the command is
safe to wire into a periodic cron / CI smoke.
"""

from __future__ import annotations

import asyncio
from enum import StrEnum
import json
from pathlib import Path
from typing import Any

import typer

from guardiabox.fileio.platform import is_ssd
from guardiabox.persistence.database import sqlcipher_available
from guardiabox.persistence.repositories import AuditRepository, UserRepository
from guardiabox.security.audit import verify
from guardiabox.ui.cli._session import open_vault_session, resolve_vault_paths
from guardiabox.ui.cli.io import ExitCode, exit_for
from guardiabox.ui.cli.main import app


class _OutputFormat(StrEnum):
    """Render format. Aligned with `history --format` and `user list --format`."""

    TABLE = "table"
    JSON = "json"


@app.command("doctor")
def doctor_command(
    verify_audit: bool = typer.Option(
        False,
        "--verify-audit",
        help="Walk the audit log and verify the hash chain (unlocks the vault).",
    ),
    report_ssd: bool = typer.Option(
        False,
        "--report-ssd",
        help="Probe the data_dir's storage type (SSD / HDD / unknown) per spec 004.",
    ),
    output: _OutputFormat = typer.Option(
        _OutputFormat.TABLE,
        "--format",
        case_sensitive=False,
        help="Format de sortie (table ou json).",
    ),
    data_dir: Path | None = typer.Option(None, "--data-dir", show_default=False),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire le mot de passe administrateur depuis stdin (si --verify-audit).",
    ),
) -> None:
    """Afficher l'état du coffre et, avec --verify-audit, vérifier la chaîne."""
    paths = resolve_vault_paths(data_dir)

    facts: dict[str, Any] = {
        "data_dir": str(paths.data_dir),
        "db_present": paths.db.is_file(),
        "db_path": str(paths.db),
        "admin_config_present": paths.admin_config.is_file(),
        "admin_config_path": str(paths.admin_config),
        "sqlcipher_available": sqlcipher_available(),
    }

    if report_ssd:
        probe_target = paths.data_dir if paths.data_dir.exists() else paths.data_dir.parent
        verdict = is_ssd(probe_target)
        facts["is_ssd"] = verdict
        if verdict is True:
            facts["storage_label"] = "SSD (mémoire flash) -- crypto-erase recommandé"
        elif verdict is False:
            facts["storage_label"] = "HDD (rotational) -- overwrite DoD efficace"
        else:
            facts["storage_label"] = (
                "indéterminé -- traité comme flash par prudence (NIST SP 800-88r2)"
            )

    if output is _OutputFormat.JSON and not verify_audit:
        typer.echo(json.dumps(facts, indent=2, default=str))
        return

    typer.echo(f"Répertoire de données : {facts['data_dir']}")
    typer.echo(
        f"Base de données       : {facts['db_path']} "
        f"({'présent' if facts['db_present'] else 'absent'})"
    )
    typer.echo(
        f"Configuration admin   : {facts['admin_config_path']} "
        f"({'présent' if facts['admin_config_present'] else 'absent'})"
    )
    typer.echo(f"SQLCipher disponible  : {'oui' if facts['sqlcipher_available'] else 'non'}")
    if report_ssd:
        typer.echo(f"Type de support       : {facts['storage_label']}")

    if not verify_audit:
        return

    if not paths.admin_config.is_file() or not paths.db.is_file():
        typer.echo(
            "Erreur : coffre non initialisé — lancer `guardiabox init`.",
            err=True,
        )
        raise typer.Exit(code=ExitCode.CONFIG_ERROR)

    try:
        result = asyncio.run(_verify_flow(data_dir=data_dir, password_stdin=password_stdin))
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    typer.echo(f"\nEntrées vérifiées : {result['checked']}")
    typer.echo(f"Utilisateurs      : {result['users']}")
    if result["ok"]:
        typer.echo("Chaîne d'audit    : [OK] intègre")
        return
    typer.echo(
        f"Chaîne d'audit    : [FAIL] altération détectée à sequence={result['first_bad']}",
        err=True,
    )
    raise typer.Exit(code=ExitCode.DATA_ERROR)


async def _verify_flow(
    *,
    data_dir: Path | None,
    password_stdin: bool,
) -> dict[str, object]:
    async with open_vault_session(data_dir, password_stdin=password_stdin) as (
        vault,
        session,
        _engine,
    ):
        verify_result = await verify(session, vault.admin_key)
        user_repo = UserRepository(session, vault.admin_key)
        audit_repo = AuditRepository(session, vault.admin_key)
        users = await user_repo.list_all()
        latest_entry = await audit_repo.latest()
        return {
            "ok": verify_result.ok,
            "first_bad": verify_result.first_bad_sequence,
            "checked": verify_result.entries_checked,
            "users": len(users),
            "latest_sequence": latest_entry.sequence if latest_entry else 0,
        }
