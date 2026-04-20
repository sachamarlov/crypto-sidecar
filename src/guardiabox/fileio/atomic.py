"""Atomic file writes.

The pattern: write to a temporary file in the same directory, fsync it, then
:func:`os.replace` it onto the target. On POSIX this is atomic; on Windows
:func:`os.replace` is atomic since Python 3.3.

Critical for the ``.crypt`` writer: a half-written ciphertext file would be
indistinguishable from a corrupted one and bias users into discarding intact
backups.
"""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Atomically write ``data`` to ``path`` (replacing any existing file)."""
    raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")


def atomic_writer(path: Path) -> BinaryIO:
    """Return a context-managed writer that atomically commits on close."""
    raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")
