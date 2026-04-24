"""Path validation utilities.

Every user-supplied path enters the system through :func:`resolve_within`,
which guarantees that the resolved path lies under an allowed root and
that no reparse point (symlink, junction, mount point, OneDrive
placeholder, …) hides an escape outside it. Refusal is *fail-fast* — we
raise rather than silently sanitise.

On Windows, ``Path.is_symlink()`` only catches symbolic links. NTFS
junctions (``mklink /J``) and volume mount points use a different reparse
tag (``IO_REPARSE_TAG_MOUNT_POINT``) and slip through. We therefore test
``FILE_ATTRIBUTE_REPARSE_POINT`` in the file-attribute bitmask on
Windows, which covers every reparse variant, and fall back to
``is_symlink()`` on POSIX.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys

from guardiabox.core.exceptions import PathTraversalError, SymlinkEscapeError

__all__ = [
    "PathTraversalError",
    "SymlinkEscapeError",
    "resolve_within",
]

# Windows FILE_ATTRIBUTE_REPARSE_POINT — symlinks, junctions, mount points,
# and any future reparse variant all set this bit.
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def resolve_within(candidate: Path, root: Path, *, allow_symlinks: bool = False) -> Path:
    """Resolve ``candidate`` and ensure it is contained within ``root``.

    Args:
        candidate: Path supplied by the user. May be relative or absolute. If
            relative, it is resolved against ``root``.
        root: The only directory the result is allowed to live under.
        allow_symlinks: If ``False`` (default), reject any segment of
            ``candidate`` that resolves through a symlink or other Windows
            reparse point (junction, mount point, OneDrive placeholder)
            strictly below ``root``. If ``True``, such links are followed
            but the final destination must still fall under ``root``.

    Returns:
        The fully-resolved absolute path, guaranteed to be within ``root``.

    Raises:
        PathTraversalError: If the resolved path escapes ``root``.
        SymlinkEscapeError: If a reparse point is encountered when not allowed.
    """
    resolved_root = root.resolve(strict=False)

    absolute_candidate = candidate if candidate.is_absolute() else resolved_root / candidate

    if not allow_symlinks:
        _reject_reparse_points_in_chain(absolute_candidate, resolved_root)

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


def _is_reparse_point(path: Path) -> bool:
    """Return True if ``path`` is a symlink (POSIX) or any reparse point (Windows).

    Non-existent paths return False (there's nothing to test). OSError
    probes — permission denied, stale NFS handle, etc. — return False so
    the downstream containment check is the one that speaks.
    """
    # Assigning ``sys.platform`` to a local dodges mypy's build-host
    # narrowing (same trick used in ``fileio.platform``).
    platform = sys.platform
    try:
        if platform == "win32":
            st = os.lstat(path)
            attrs = getattr(st, "st_file_attributes", 0)
            return bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)
        return path.is_symlink()
    except OSError:
        return False


def _reject_reparse_points_in_chain(absolute_path: Path, root: Path) -> None:
    """Reject a non-resolved chain that contains a reparse point below ``root``.

    Any segment in the path chain between ``absolute_path`` (inclusive)
    and ``root`` (exclusive) that is a symlink (POSIX) or reparse point
    (Windows symlink / junction / mount point) triggers
    :class:`SymlinkEscapeError`. The root itself is assumed trusted and
    is not inspected.
    """
    current = absolute_path
    while current != root:
        if _is_reparse_point(current):
            raise SymlinkEscapeError(f"reparse point found in path chain: {current}")
        parent = current.parent
        if parent == current:
            # Filesystem root reached without crossing ``root``; the
            # containment check that runs next will flag the traversal.
            return
        current = parent
