"""TUI launcher.

Implementation deliberately deferred — see ``docs/specs/000-tui/plan.md``.
"""

from __future__ import annotations


def run() -> None:
    """Start the Textual application loop."""
    from guardiabox.ui.tui.app import GuardiaBoxApp  # local import for fast CLI startup

    GuardiaBoxApp().run()


if __name__ == "__main__":
    run()
