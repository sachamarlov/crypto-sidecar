"""Tests for :mod:`guardiabox.fileio.streaming`."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardiabox.fileio.streaming import iter_chunks


def test_iter_chunks_small_file(tmp_path: Path) -> None:
    target = tmp_path / "file.bin"
    target.write_bytes(b"abcdefghij")
    assert list(iter_chunks(target, chunk_size=4)) == [b"abcd", b"efgh", b"ij"]


def test_iter_chunks_exact_multiple(tmp_path: Path) -> None:
    target = tmp_path / "file.bin"
    target.write_bytes(b"abcd" * 3)
    assert list(iter_chunks(target, chunk_size=4)) == [b"abcd", b"abcd", b"abcd"]


def test_iter_chunks_empty_file(tmp_path: Path) -> None:
    target = tmp_path / "empty.bin"
    target.write_bytes(b"")
    assert list(iter_chunks(target, chunk_size=16)) == []


def test_iter_chunks_rejects_non_positive_chunk(tmp_path: Path) -> None:
    target = tmp_path / "file.bin"
    target.write_bytes(b"x")
    with pytest.raises(ValueError, match="positive"):
        list(iter_chunks(target, chunk_size=0))
