"""Chunked streaming I/O for files larger than working memory."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from guardiabox.core.constants import DEFAULT_CHUNK_BYTES

__all__ = ["iter_chunks"]


def iter_chunks(path: Path, chunk_size: int = DEFAULT_CHUNK_BYTES) -> Iterator[bytes]:
    """Yield ``path``'s bytes in fixed-size chunks.

    The final chunk may be shorter than ``chunk_size``. An empty file yields
    zero chunks. ``chunk_size`` must be a positive integer.
    """
    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be positive, got {chunk_size}")
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                return
            yield chunk
