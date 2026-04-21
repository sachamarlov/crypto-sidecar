"""``guardiabox encrypt`` — encrypt a file or a typed message.

The CLI delegates all cryptographic work to :mod:`guardiabox.core.operations`.
Responsibilities handled here:

* Resolve user-supplied paths against the current working directory and reject
  any traversal (``../../etc/passwd`` style inputs).
* Prompt for the password (no-echo, confirmation) or read it from stdin.
* Map domain exceptions to localised French messages and process exit codes.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
import sys

import typer

from guardiabox.core.exceptions import (
    PathTraversalError,
    SymlinkEscapeError,
    WeakPasswordError,
)
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.core.operations import encrypt_file, encrypt_message
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.ui.cli.main import app


class KdfChoice(StrEnum):
    """Selectable KDF flavours on the CLI surface."""

    PBKDF2 = "pbkdf2"
    ARGON2ID = "argon2id"


@app.command("encrypt")
def encrypt_command(
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
) -> None:
    """Chiffrer un fichier ou un message avec un mot de passe utilisateur."""
    try:
        if message is not None:
            target = _encrypt_message_flow(
                message=message,
                output=output,
                kdf=kdf,
                password_stdin=password_stdin,
            )
        else:
            if path is None:
                typer.echo("Erreur : fournir un chemin de fichier ou --message.", err=True)
                raise typer.Exit(1)
            target = _encrypt_file_flow(
                path=path,
                output=output,
                kdf=kdf,
                password_stdin=password_stdin,
            )
    except WeakPasswordError as exc:
        typer.echo(f"Mot de passe trop faible (score zxcvbn < 3) : {exc}", err=True)
        raise typer.Exit(1) from exc
    except (PathTraversalError, SymlinkEscapeError) as exc:
        typer.echo(f"Chemin refusé : {exc}", err=True)
        raise typer.Exit(1) from exc
    except FileNotFoundError as exc:
        typer.echo(f"Fichier introuvable : {exc}", err=True)
        raise typer.Exit(1) from exc
    except KeyboardInterrupt as exc:
        raise typer.Exit(130) from exc
    except OSError as exc:
        typer.echo(f"Erreur disque : {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"Chiffré : {target}")


def _encrypt_file_flow(
    *,
    path: Path,
    output: Path | None,
    kdf: KdfChoice,
    password_stdin: bool,
) -> Path:
    cwd = Path.cwd().resolve()
    safe_source = resolve_within(path, cwd)
    if not safe_source.is_file():
        typer.echo(f"Fichier introuvable : {safe_source}", err=True)
        raise typer.Exit(1)

    safe_output = resolve_within(output, cwd) if output is not None else None
    password = _read_password(stdin=password_stdin, confirm=True)
    return encrypt_file(
        safe_source,
        password,
        kdf=_build_kdf(kdf),
        dest=safe_output,
    )


def _encrypt_message_flow(
    *,
    message: str,
    output: Path | None,
    kdf: KdfChoice,
    password_stdin: bool,
) -> Path:
    if output is None:
        typer.echo("Erreur : --output est requis avec --message.", err=True)
        raise typer.Exit(1)
    cwd = Path.cwd().resolve()
    safe_output = resolve_within(output, cwd)

    raw_message = _resolve_message(message)
    password = _read_password(stdin=password_stdin, confirm=True)
    return encrypt_message(
        raw_message,
        password,
        kdf=_build_kdf(kdf),
        dest=safe_output,
    )


def _resolve_message(value: str) -> bytes:
    if value == "-":
        return sys.stdin.buffer.read()
    return value.encode("utf-8")


def _build_kdf(choice: KdfChoice) -> Pbkdf2Kdf | Argon2idKdf:
    if choice is KdfChoice.ARGON2ID:
        return Argon2idKdf()
    return Pbkdf2Kdf()


def _read_password(*, stdin: bool, confirm: bool) -> str:
    if stdin:
        raw = sys.stdin.readline()
        return raw.rstrip("\n").rstrip("\r")
    prompt_text = "Mot de passe"
    result: str = typer.prompt(
        prompt_text,
        hide_input=True,
        confirmation_prompt=confirm,
    )
    return result
