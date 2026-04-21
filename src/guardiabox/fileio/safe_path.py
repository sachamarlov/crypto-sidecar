"""Path validation utilities.

Every user-supplied path enters the system through :func:`resolve_within`,
which guarantees that the resolved path lies under an allowed root and that no
symlink escapes outside it. Refusal is *fail-fast* — we raise rather than
silently sanitise.

The two project-specific exceptions raised by this module are re-exported
through ``__all__`` so callers can ``except`` them directly without reaching
into :mod:`guardiabox.core.exceptions`.
"""

from __future__ import annotations

from pathlib import Path

from guardiabox.core.exceptions import PathTraversalError, SymlinkEscapeError

__all__ = [
    "PathTraversalError",
    "SymlinkEscapeError",
    "resolve_within",
]


def resolve_within(candidate: Path, root: Path, *, allow_symlinks: bool = False) -> Path:
    """Resolve ``candidate`` and ensure it is contained within ``root``.

    Args:
        candidate: Path supplied by the user. May be relative or absolute. If
            relative, it is resolved against ``root``.
        root: The only directory the result is allowed to live under.
        allow_symlinks: If ``False`` (default), reject any segment of
            ``candidate`` that resolves through a symlink strictly below
            ``root``. If ``True``, symlinks are followed but the final
            destination must still fall under ``root``.

    Returns:
        The fully-resolved absolute path, guaranteed to be within ``root``.

    Raises:
        PathTraversalError: If the resolved path escapes ``root``.
        SymlinkEscapeError: If a symlink is encountered when not allowed.
    """
    resolved_root = root.resolve(strict=False)

    absolute_candidate = candidate if candidate.is_absolute() else resolved_root / candidate

    if not allow_symlinks:
        _reject_symlinks_in_chain(absolute_candidate, resolved_root)

    resolved_candidate = absolute_candidate.resolve(strict=False)

    if not _is_within(resolved_candidate, resolved_root):
        raise PathTraversalError(
            f"target path escapes root: {resolved_candidate} not under {resolved_root}"
        )

    return resolved_candidate


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return path == root
    else:
        return True


def _reject_symlinks_in_chain(absolute_path: Path, root: Path) -> None:
    """Reject a non-resolved chain that contains a symlink below ``root``.

    Any segment in the path chain between ``absolute_path`` (inclusive) and
    ``root`` (exclusive) that is a symbolic link triggers
    :class:`SymlinkEscapeError`. The root itself is assumed trusted and is
    not inspected.
    """
    current = absolute_path
    while current != root:
        if current.is_symlink():
            raise SymlinkEscapeError(f"symlink found in path chain: {current}")
        parent = current.parent
        if parent == current:
            # Filesystem root reached without crossing ``root``; the
            # containment check that runs next will flag the traversal.
            return
        current = parent
