"""``guardiabox secure-delete`` — DoD-style overwrite + unlink.

Only the multi-pass overwrite path is active today (spec 004 Phase B1).
Crypto-erase ships with the keystore (spec 004 Phase B2) and is absent
from the ``--method`` switch until then.

On SSDs the CLI emits a NIST SP 800-88r2 warning (overwrite is
best-effort on flash media) and asks for confirmation unless
``--no-confirm`` is passed. On HDDs or unknown media the command
proceeds silently.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import typer

from guardiabox.core.secure_delete import (
    DEFAULT_OVERWRITE_PASSES,
    SecureDeleteMethod,
    secure_delete,
)
from guardiabox.fileio.platform import is_ssd
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.ui.cli.io import ExitCode, exit_for
from guardiabox.ui.cli.main import app


class _MethodChoice(StrEnum):
    """Methods exposed on the CLI surface. ``auto`` picks per media type."""

    AUTO = "auto"
    OVERWRITE = "overwrite"


@app.command("secure-delete")
def secure_delete_command(
    path: Path = typer.Argument(..., help="Chemin du fichier à supprimer de manière sûre."),
    method: _MethodChoice = typer.Option(
        _MethodChoice.AUTO,
        "--method",
        case_sensitive=False,
        help="Stratégie. 'auto' détecte le support ; 'overwrite' force l'écrasement DoD.",
    ),
    passes: int = typer.Option(
        DEFAULT_OVERWRITE_PASSES,
        "--passes",
        min=1,
        max=35,
        help="Nombre de passes d'écrasement (zéro / un / aléatoire en cycle).",
    ),
    no_confirm: bool = typer.Option(
        False,
        "--no-confirm",
        help="Ne pas demander de confirmation, même sur SSD détecté.",
    ),
) -> None:
    """Supprimer un fichier de façon sécurisée (écrasement DoD + unlink)."""
    try:
        _dispatch(path=path, method=method, passes=passes, no_confirm=no_confirm)
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    typer.echo(f"Supprimé : {path} ({passes} passe(s) d'écrasement)")


def _dispatch(
    *,
    path: Path,
    method: _MethodChoice,
    passes: int,
    no_confirm: bool,
) -> None:
    cwd = Path.cwd().resolve()
    safe = resolve_within(path, cwd)
    if not safe.is_file():
        typer.echo(f"Fichier introuvable : {safe}", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE)

    ssd = is_ssd(safe)
    if ssd is True:
        _warn_ssd(no_confirm=no_confirm)

    if method is _MethodChoice.AUTO:
        # Until crypto-erase lands (Phase B2), 'auto' always falls back to
        # overwrite — we keep the flag so the future extension is seamless.
        resolved_method = SecureDeleteMethod.OVERWRITE_DOD
    else:
        resolved_method = SecureDeleteMethod.OVERWRITE_DOD

    secure_delete(safe, method=resolved_method, passes=passes)


def _warn_ssd(*, no_confirm: bool) -> None:
    msg = (
        "Attention : le support détecté est un SSD. L'écrasement est un effort "
        "best-effort sur mémoire flash (NIST SP 800-88r2 §5.2). L'effacement "
        "cryptographique (crypto-erase) sera disponible après l'implémentation "
        "de la base utilisateurs (spec 000-multi-user)."
    )
    typer.echo(msg, err=True)
    if no_confirm:
        return
    if not typer.confirm("Poursuivre l'écrasement quand même ?", default=False):
        raise typer.Exit(code=ExitCode.GENERIC)
