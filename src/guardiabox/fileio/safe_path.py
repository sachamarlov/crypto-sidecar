"""Path validation utilities.

Every user-supplied path enters the system through :func:`resolve_within`,
which guarantees that the resolved path lies under an allowed root and that no
symlink escapes outside it. Refusal is *fail-fast* — we raise rather than
silently sanitise.
"""

from __future__ import annotations

from pathlib import Path

# Imported for documentation; the implementation will raise these.
from guardiabox.core.exceptions import (
    PathTraversalError as PathTraversalError,
    SymlinkEscapeError as SymlinkEscapeError,
)


def resolve_within(candidate: Path, root: Path, *, allow_symlinks: bool = False) -> Path:
    """Resolve ``candidate`` and ensure it is contained within ``root``.

    Args:
        candidate: Path supplied by the user. May be relative or absolute.
        root: The only directory the result is allowed to live under.
        allow_symlinks: If ``False`` (default), reject any symlink in the
            resolved chain. If ``True``, follow symlinks but still verify the
            final destination is under ``root``.

    Returns:
        The fully-resolved absolute path, guaranteed to be within ``root``.

    Raises:
        PathTraversalError: If the resolved path escapes ``root``.
        SymlinkEscapeError: If a symlink is encountered when not allowed.
    """
    raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")
