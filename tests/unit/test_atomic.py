"""Tests for :mod:`guardiabox.fileio.atomic`."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardiabox.fileio.atomic import atomic_write_bytes, atomic_writer


def test_atomic_write_creates_file(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    atomic_write_bytes(target, b"hello")
    assert target.read_bytes() == b"hello"


def test_atomic_write_replaces_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    target.write_bytes(b"original")
    atomic_write_bytes(target, b"replaced")
    assert target.read_bytes() == b"replaced"


def _write_partial_and_raise(target: Path, payload: bytes, marker: str) -> None:
    """Helper used to keep each ``pytest.raises`` block a single statement."""
    with atomic_writer(target) as out:
        out.write(payload)
        raise RuntimeError(marker)


def test_exception_mid_write_leaves_target_untouched(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    target.write_bytes(b"original")
    with pytest.raises(RuntimeError, match="boom"):
        _write_partial_and_raise(target, b"partial data", "boom")
    assert target.read_bytes() == b"original"
    # No leftover temp files in the directory.
    leftover = [p for p in tmp_path.iterdir() if p.suffix == ".tmp.gbox"]
    assert leftover == []


def test_exception_mid_write_leaves_no_file_when_target_absent(
    tmp_path: Path,
) -> None:
    target = tmp_path / "fresh.bin"
    with pytest.raises(RuntimeError, match="boom"):
        _write_partial_and_raise(target, b"xx", "boom")
    assert not target.exists()


def test_atomic_writer_creates_missing_parent_dir(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "dir" / "out.bin"
    atomic_write_bytes(target, b"xyz")
    assert target.read_bytes() == b"xyz"
