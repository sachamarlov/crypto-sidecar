"""Chunked streaming I/O for files larger than working memory."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from guardiabox.core.constants import DEFAULT_CHUNK_BYTES


def iter_chunks(path: Path, chunk_size: int = DEFAULT_CHUNK_BYTES) -> Iterator[bytes]:
    """Yield ``path``'s bytes in fixed-size chunks (last chunk may be smaller)."""
    raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")
