"""Tests for :mod:`guardiabox.fileio.atomic`."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardiabox.fileio.atomic import (
    _best_effort_wipe_and_unlink,
    atomic_write_bytes,
    atomic_writer,
)


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


def test_wipe_helper_zeroes_then_unlinks(tmp_path: Path) -> None:
    """Fix-1.N -- wipe-and-unlink overwrites before removing the file."""
    victim = tmp_path / "plaintext.bin"
    victim.write_bytes(b"TOP-SECRET-PAYLOAD" * 1000)  # ~18 KB
    _best_effort_wipe_and_unlink(victim)
    assert not victim.exists(), "file must be unlinked after the wipe"


def test_wipe_helper_handles_missing_file(tmp_path: Path) -> None:
    """The helper must never raise even when the target is already gone."""
    ghost = tmp_path / "never-existed.bin"
    _best_effort_wipe_and_unlink(ghost)
    assert not ghost.exists()


def test_wipe_helper_handles_empty_file(tmp_path: Path) -> None:
    """An empty file must just be unlinked (no write needed)."""
    victim = tmp_path / "zero.bin"
    victim.write_bytes(b"")
    _best_effort_wipe_and_unlink(victim)
    assert not victim.exists()


def _write_and_raise_sensitive(target: Path) -> None:
    """Trigger an atomic_writer rollback after writing plaintext bytes."""
    with atomic_writer(target) as out:
        out.write(b"SENSITIVE-PLAINTEXT" * 4096)
        raise RuntimeError("mid-write rollback")


def test_exception_mid_write_routes_through_wipe_helper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end -- a mid-write exception must call the wipe helper,
    not just a bare unlink. We intercept the helper to confirm it runs
    with the temp path and that no .tmp.gbox survives afterwards."""
    import guardiabox.fileio.atomic as atomic_mod

    called_with: list[Path] = []
    real_helper = atomic_mod._best_effort_wipe_and_unlink

    def spy(path: Path) -> None:
        called_with.append(path)
        real_helper(path)

    monkeypatch.setattr(atomic_mod, "_best_effort_wipe_and_unlink", spy)

    target = tmp_path / "secret.decrypt"
    with pytest.raises(RuntimeError, match="mid-write"):
        _write_and_raise_sensitive(target)

    assert len(called_with) == 1, "wipe helper must be called exactly once"
    assert called_with[0].name.endswith(".tmp.gbox"), called_with[0].name
    assert not target.exists()
    assert [p for p in tmp_path.iterdir() if p.name.endswith(".tmp.gbox")] == []
