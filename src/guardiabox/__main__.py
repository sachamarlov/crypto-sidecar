"""Entry point for ``python -m guardiabox`` — defaults to the CLI."""

from __future__ import annotations

from guardiabox.ui.cli.main import app


def main() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main()
