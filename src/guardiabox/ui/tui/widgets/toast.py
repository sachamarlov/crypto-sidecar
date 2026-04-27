"""Auto-dismissing toast notification (T-000tui.05).

Lightweight wrapper around :class:`Static` that mounts itself in the
``notification`` layer and removes itself after a configurable timeout.
Four variants are exposed via :class:`ToastVariant`; each maps to a
border color in the bundled CSS.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from textual.widgets import Static


class ToastVariant(StrEnum):
    """Visual + semantic variant of a toast."""

    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


class Toast(Static):
    """Top-anchored notification that fades after ``timeout`` seconds.

    The widget self-mounts on construction by calling
    :meth:`textual.app.App.mount`. Pass a screen as the second argument
    to scope the toast to the current modal:

    .. code-block:: python

        Toast.show(self.app, "Fichier chiffré.", variant=ToastVariant.SUCCESS)

    Internally each variant adds a CSS class (``toast-success``, ...)
    that pulls the matching border color from :file:`app.tcss`.
    """

    DEFAULT_TIMEOUT_SECONDS: float = 3.5

    def __init__(
        self,
        message: str,
        *,
        variant: ToastVariant = ToastVariant.INFO,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        super().__init__(message, classes=f"toast toast-{variant.value}")
        self._timeout = timeout

    def on_mount(self) -> None:
        """Schedule the auto-dismiss timer."""
        self.set_timer(self._timeout, self.remove)

    @classmethod
    def show(
        cls,
        host: Any,
        message: str,
        *,
        variant: ToastVariant = ToastVariant.INFO,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> Toast:
        """Construct + mount a toast on ``host`` (App or Screen).

        Returns the mounted instance so the caller may dismiss it
        early with ``toast.remove()``.
        """
        toast = cls(message, variant=variant, timeout=timeout)
        host.mount(toast)
        return toast
