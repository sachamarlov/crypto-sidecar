"""``guardiabox decrypt`` — decrypt a ``.crypt`` file or emit to stdout."""

from __future__ import annotations

from pathlib import Path
import sys

import typer

from guardiabox.core.operations import decrypt_file, decrypt_message
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.ui.cli.io import ExitCode, exit_for, read_password
from guardiabox.ui.cli.main import app


@app.command("decrypt")
def decrypt_command(
    path: Path = typer.Argument(
        ...,
        help="Chemin du fichier .crypt à déchiffrer.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Destination. Défaut : remplace .crypt par .decrypt.",
        show_default=False,
    ),
    to_stdout: bool = typer.Option(
        False,
        "--stdout",
        "-m",
        "--message",
        help="Écrire le contenu déchiffré sur stdout sans toucher au disque.",
    ),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire le mot de passe depuis stdin (pas de prompt interactif).",
    ),
) -> None:
    """Déchiffrer un fichier ``.crypt`` vers son contenu d'origine."""
    try:
        target = _dispatch(
            path=path,
            output=output,
            to_stdout=to_stdout,
            password_stdin=password_stdin,
        )
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    if target is not None:
        typer.echo(f"Déchiffré : {target}")


def _dispatch(
    *,
    path: Path,
    output: Path | None,
    to_stdout: bool,
    password_stdin: bool,
) -> Path | None:
    cwd = Path.cwd().resolve()
    safe_source = resolve_within(path, cwd)
    if not safe_source.is_file():
        typer.echo(f"Fichier introuvable : {safe_source}", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE)

    password = read_password(stdin=password_stdin)

    if to_stdout:
        plaintext = decrypt_message(safe_source, password)
        sys.stdout.buffer.write(plaintext)
        sys.stdout.flush()
        return None

    safe_output = resolve_within(output, cwd) if output is not None else None
    return decrypt_file(safe_source, password, dest=safe_output)
