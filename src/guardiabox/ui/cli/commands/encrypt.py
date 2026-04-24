"""``guardiabox encrypt`` — encrypt a file or a typed message.

The CLI delegates all cryptographic work to :mod:`guardiabox.core.operations`.
Responsibilities handled here:

* Resolve user-supplied paths against the current working directory and reject
  any traversal (``../../etc/passwd`` style inputs).
* Prompt for the password (no-echo, confirmation) or read it from stdin.
* Map domain exceptions to exit codes via :func:`guardiabox.ui.cli.io.exit_for`.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
import sys

import typer

from guardiabox.core.constants import MAX_IN_MEMORY_MESSAGE_BYTES
from guardiabox.core.exceptions import MessageTooLargeError
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.core.operations import encrypt_file, encrypt_message
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.ui.cli.io import ExitCode, exit_for, read_password
from guardiabox.ui.cli.main import app


class KdfChoice(StrEnum):
    """Selectable KDF flavours on the CLI surface."""

    PBKDF2 = "pbkdf2"
    ARGON2ID = "argon2id"


@app.command("encrypt")
def encrypt_command(  # noqa: PLR0917 -- Typer commands expose one param per flag
    path: Path | None = typer.Argument(
        None,
        help="Chemin du fichier à chiffrer. Ignoré si --message est utilisé.",
        show_default=False,
    ),
    message: str | None = typer.Option(
        None,
        "--message",
        "-m",
        help="Chiffrer un message littéral au lieu d'un fichier (utiliser '-' pour lire stdin).",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Destination. Défaut : <fichier>.crypt.",
        show_default=False,
    ),
    kdf: KdfChoice = typer.Option(
        KdfChoice.PBKDF2,
        "--kdf",
        case_sensitive=False,
        help="Fonction de dérivation de clé.",
    ),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire le mot de passe depuis stdin (pas de prompt interactif).",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Écraser la destination si elle existe déjà.",
    ),
) -> None:
    """Chiffrer un fichier ou un message avec un mot de passe utilisateur."""
    try:
        target = _dispatch(
            path=path,
            message=message,
            output=output,
            kdf=kdf,
            password_stdin=password_stdin,
            force=force,
        )
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    typer.echo(f"Chiffré : {target}")


def _dispatch(
    *,
    path: Path | None,
    message: str | None,
    output: Path | None,
    kdf: KdfChoice,
    password_stdin: bool,
    force: bool,
) -> Path:
    if message is not None:
        return _encrypt_message_flow(
            message=message,
            output=output,
            kdf=kdf,
            password_stdin=password_stdin,
            force=force,
        )
    if path is None:
        typer.echo("Erreur : fournir un chemin de fichier ou --message.", err=True)
        raise typer.Exit(code=ExitCode.USAGE)
    return _encrypt_file_flow(
        path=path,
        output=output,
        kdf=kdf,
        password_stdin=password_stdin,
        force=force,
    )


def _encrypt_file_flow(
    *,
    path: Path,
    output: Path | None,
    kdf: KdfChoice,
    password_stdin: bool,
    force: bool,
) -> Path:
    cwd = Path.cwd().resolve()
    safe_source = resolve_within(path, cwd)
    if not safe_source.is_file():
        typer.echo(f"Fichier introuvable : {safe_source}", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE)

    password = read_password(stdin=password_stdin, confirm=True)
    return encrypt_file(
        safe_source,
        password,
        root=cwd,
        kdf=_build_kdf(kdf),
        dest=output,
        force=force,
    )


def _encrypt_message_flow(
    *,
    message: str,
    output: Path | None,
    kdf: KdfChoice,
    password_stdin: bool,
    force: bool,
) -> Path:
    if output is None:
        typer.echo("Erreur : --output est requis avec --message.", err=True)
        raise typer.Exit(code=ExitCode.USAGE)
    cwd = Path.cwd().resolve()

    raw_message = _resolve_message(message)
    password = read_password(stdin=password_stdin, confirm=True)
    return encrypt_message(
        raw_message,
        password,
        root=cwd,
        dest=output,
        kdf=_build_kdf(kdf),
        force=force,
    )


def _resolve_message(value: str) -> bytes:
    if value == "-":
        # Read at most MAX + 1 to detect overflow without allocating an
        # unbounded buffer. A caller piping a multi-gigabyte stream
        # should route through encrypt_file instead.
        data = sys.stdin.buffer.read(MAX_IN_MEMORY_MESSAGE_BYTES + 1)
        if len(data) > MAX_IN_MEMORY_MESSAGE_BYTES:
            raise MessageTooLargeError(
                f"stdin payload exceeds in-memory limit "
                f"{MAX_IN_MEMORY_MESSAGE_BYTES}; use encrypt on a file instead"
            )
        return data
    return value.encode("utf-8")


def _build_kdf(choice: KdfChoice) -> Pbkdf2Kdf | Argon2idKdf:
    if choice is KdfChoice.ARGON2ID:
        return Argon2idKdf()
    return Pbkdf2Kdf()
