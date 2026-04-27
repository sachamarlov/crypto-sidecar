"""TUI launcher (entry point ``guardiabox-tui``).

Probes the terminal for reduced-motion support (``TERM=dumb``) before
instantiating the app so the framework's animations are disabled in
contexts that cannot render them (CI logs, screen-readers via braille
displays, plain ``cmd.exe``).
"""

from __future__ import annotations

import contextlib
import os


def _is_reduced_motion() -> bool:
    """Return True when the host terminal cannot render Textual animations.

    The convention is ``TERM=dumb`` for the dumbest possible terminal.
    Some screen-readers and CI runners also set ``CI=true`` -- we check
    both as a defensive belt-and-suspenders.
    """
    term = os.environ.get("TERM", "").lower()
    if term == "dumb":
        return True
    return os.environ.get("CI", "").lower() in {"1", "true", "yes"}


def run() -> None:
    """Start the Textual application loop."""
    from guardiabox.ui.tui.app import GuardiaBoxApp

    app = GuardiaBoxApp()
    if _is_reduced_motion():
        # Textual exposes ``animation_level`` on the app instance; setting
        # it to "none" disables every transition, fade, and slide.
        # Older Textual versions miss the attribute -- swallow that case.
        with contextlib.suppress(Exception):
            app.animation_level = "none"
    app.run()


if __name__ == "__main__":
    run()
