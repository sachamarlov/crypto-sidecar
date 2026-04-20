"""Typer application entry point.

The CLI is the canonical interface required by the academic brief (CDC):
``encrypt`` / ``decrypt`` / ``quit`` are reachable from a console menu, but
each operation is also addressable as a top-level command for scripting.

Implementation deliberately deferred — see ``docs/specs/000-cli/plan.md``.
"""

from __future__ import annotations

import typer

from guardiabox import __version__

app = typer.Typer(
    name="guardiabox",
    help="Local secure vault — encrypt, decrypt, store, and share files offline.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    *,
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit."),
) -> None:
    """GuardiaBox CLI entry point."""
    if version:
        typer.echo(f"guardiabox {__version__}")
        raise typer.Exit


# Subcommands are registered from sibling modules to keep this file slim.


if __name__ == "__main__":
    app()
