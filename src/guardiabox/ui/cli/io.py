"""Shared I/O helpers for the CLI layer.

Centralises three concerns that were previously duplicated across the
per-command modules:

* :class:`ExitCode` — POSIX-ish exit code constants, used by every
  command so the mapping stays uniform.
* :func:`exit_for` — maps a domain exception to a localised French
  user-facing message and the matching exit code. Crucially enforces
  the **anti-oracle** guarantee for :class:`DecryptionError` /
  :class:`IntegrityError`: both surface the exact same stderr line, so
  an attacker cannot distinguish "wrong password" from "tampered
  ciphertext" by observing the CLI's output.
* :func:`read_password` — single password-prompt helper (no-echo,
  optional confirmation, optional stdin read).
"""

from __future__ import annotations

from enum import IntEnum
import sys
from typing import NoReturn

import typer

from guardiabox.core.exceptions import (
    CorruptedContainerError,
    DecryptionError,
    DestinationCollidesWithSourceError,
    GuardiaBoxError,
    IntegrityError,
    InvalidContainerError,
    PathTraversalError,
    SymlinkEscapeError,
    UnknownKdfError,
    UnsupportedVersionError,
    WeakKdfParametersError,
    WeakPasswordError,
)

__all__ = [
    "ANTI_ORACLE_MESSAGE",
    "ExitCode",
    "exit_for",
    "read_password",
]


class ExitCode(IntEnum):
    """POSIX-aligned process exit codes used by every GuardiaBox CLI command.

    The mapping follows the table in ``docs/specs/000-cli/plan.md``:

    * ``0`` success
    * ``1`` generic / unrecoverable error
    * ``2`` wrong password or decryption failed (anti-oracle branch)
    * ``3`` file not found, path refused
    * ``64`` usage error (EX_USAGE)
    * ``65`` data error (EX_DATAERR) — malformed container, unknown KDF, etc.
    * ``78`` configuration error (EX_CONFIG)
    * ``130`` interrupted by user (SIGINT)
    """

    OK = 0
    GENERIC = 1
    AUTH_FAILED = 2
    PATH_OR_FILE = 3
    USAGE = 64
    DATA_ERROR = 65
    CONFIG_ERROR = 78
    INTERRUPTED = 130


# Single source of truth for the "decryption failed" message. Referenced by
# tests asserting the anti-oracle guarantee — any change here must keep the
# message identical for both wrong-password and tampered-ciphertext failures.
ANTI_ORACLE_MESSAGE: str = "Échec du déchiffrement : mot de passe incorrect ou données altérées."


def exit_for(exc: BaseException) -> NoReturn:
    """Emit the localised message for ``exc`` and exit with the mapped code.

    Never returns — always raises :class:`typer.Exit`. Pass-through for
    already-wrapped :class:`typer.Exit` so a caller that already
    requested a specific exit code keeps it.
    """
    if isinstance(exc, typer.Exit):
        raise exc

    if isinstance(exc, KeyboardInterrupt):
        raise typer.Exit(code=ExitCode.INTERRUPTED) from exc

    if isinstance(exc, WeakPasswordError):
        typer.echo(f"Mot de passe trop faible (score zxcvbn < 3) : {exc}", err=True)
        raise typer.Exit(code=ExitCode.GENERIC) from exc

    if isinstance(exc, (PathTraversalError, SymlinkEscapeError)):
        typer.echo(f"Chemin refusé : {exc}", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE) from exc

    if isinstance(exc, DestinationCollidesWithSourceError):
        typer.echo(
            f"Destination identique à la source (écrasement refusé) : {exc}",
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE) from exc

    if isinstance(exc, FileNotFoundError):
        typer.echo(f"Fichier introuvable : {exc}", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE) from exc

    if isinstance(exc, (InvalidContainerError, UnsupportedVersionError)):
        typer.echo(f"Conteneur invalide : {exc}", err=True)
        raise typer.Exit(code=ExitCode.DATA_ERROR) from exc

    if isinstance(exc, (UnknownKdfError, WeakKdfParametersError)):
        typer.echo(f"Paramètres KDF non supportés : {exc}", err=True)
        raise typer.Exit(code=ExitCode.DATA_ERROR) from exc

    if isinstance(exc, CorruptedContainerError):
        typer.echo(f"Conteneur corrompu : {exc}", err=True)
        raise typer.Exit(code=ExitCode.DATA_ERROR) from exc

    # Anti-oracle: DecryptionError (wrong password OR tag mismatch) and
    # IntegrityError (explicit tamper detection) collapse into the exact
    # same user-facing output. No exception detail is surfaced — that
    # would leak information about which failure mode fired.
    if isinstance(exc, (DecryptionError, IntegrityError)):
        typer.echo(ANTI_ORACLE_MESSAGE, err=True)
        raise typer.Exit(code=ExitCode.AUTH_FAILED) from exc

    if isinstance(exc, OSError):
        typer.echo(f"Erreur disque : {exc}", err=True)
        raise typer.Exit(code=ExitCode.GENERIC) from exc

    if isinstance(exc, GuardiaBoxError):
        typer.echo(f"Erreur GuardiaBox : {exc}", err=True)
        raise typer.Exit(code=ExitCode.GENERIC) from exc

    # Unknown exception — should not happen in normal flow; surface it
    # rather than hide it under a generic code.
    typer.echo(f"Erreur inattendue : {type(exc).__name__}: {exc}", err=True)
    raise typer.Exit(code=ExitCode.GENERIC) from exc


def read_password(*, stdin: bool, confirm: bool = False, prompt: str = "Mot de passe") -> str:
    """Return a password from stdin or an interactive no-echo prompt.

    Stripping is conservative: only the trailing newline / carriage return
    of the stdin line is removed, other whitespace is kept verbatim so a
    legitimate trailing-space password is preserved.
    """
    if stdin:
        raw = sys.stdin.readline()
        if raw.endswith("\r\n"):
            return raw[:-2]
        if raw.endswith("\n"):
            return raw[:-1]
        return raw
    result: str = typer.prompt(
        prompt,
        hide_input=True,
        confirmation_prompt=confirm,
    )
    return result
