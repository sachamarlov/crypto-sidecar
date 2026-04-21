"""Atomic file writes.

The pattern: write to a temporary file in the same directory, fsync it, then
:func:`os.replace` it onto the target. On POSIX this is atomic; on Windows
:func:`os.replace` is atomic since Python 3.3.

Critical for the ``.crypt`` writer: a half-written ciphertext file would be
indistinguishable from a corrupted one and could bias users into discarding
intact backups.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, suppress
import os
from pathlib import Path
import tempfile
from typing import IO

__all__ = ["atomic_write_bytes", "atomic_writer"]

_TEMP_SUFFIX: str = ".tmp.gbox"


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Atomically write ``data`` to ``path`` (replacing any existing file)."""
    with atomic_writer(path) as out:
        out.write(data)


@contextmanager
def atomic_writer(path: Path) -> Iterator[IO[bytes]]:
    """Return a context-managed writer that atomically commits on close.

    The caller writes bytes to the yielded file-like object. On successful
    exit, the temp file is fsync'd then renamed onto ``path``. On any
    exception, the temp file is removed and ``path`` is left untouched.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # `delete=False` because we replace (or unlink) the file ourselves, and we
    # intentionally close + rename outside of a context manager so this sits
    # below a single try/except that encompasses the whole commit flow.
    tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115 — lifecycle owned below
        mode="wb",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=_TEMP_SUFFIX,
        delete=False,
    )
    tmp_path = Path(tmp.name)
    try:
        # Type note: NamedTemporaryFile objects expose the BinaryIO surface we
        # need (write, flush, fileno) but have their own wrapper class. Cast
        # via the IO[bytes] alias to keep mypy strict happy.
        io_obj: IO[bytes] = tmp
        yield io_obj
        io_obj.flush()
        os.fsync(io_obj.fileno())
        io_obj.close()
        Path(tmp_path).replace(path)
        _fsync_dir(path.parent)
    except BaseException:
        # Close then remove the temp file; never leave partial state behind.
        with suppress(OSError):
            tmp.close()
        with suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        raise


def _fsync_dir(directory: Path) -> None:
    """Flush directory metadata so the rename is durable on POSIX.

    On Windows, directories cannot be opened with ``os.open``; the rename is
    durable once :func:`os.replace` returns, so this is a no-op.
    """
    if os.name != "posix":
        return
    # ``os.O_DIRECTORY`` is POSIX-only; on Windows mypy does not know about it.
    o_directory: int = getattr(os, "O_DIRECTORY", 0)
    fd = os.open(str(directory), o_directory)  # pragma: no cover — POSIX only
    try:  # pragma: no cover
        os.fsync(fd)  # pragma: no cover
    finally:  # pragma: no cover
        os.close(fd)  # pragma: no cover
