"""Atomic file writes.

The pattern: write to a temporary file in the same directory, fsync it, then
:func:`os.replace` it onto the target. On POSIX this is atomic; on Windows
:func:`os.replace` is atomic since Python 3.3.

Critical for the ``.crypt`` writer: a half-written ciphertext file would be
indistinguishable from a corrupted one and could bias users into discarding
intact backups. Critical also for the ``decrypt`` path: if the user hits
Ctrl+C mid-decrypt, the temp file may contain partial **plaintext**. The
exception handler therefore **wipes** the temp file (single zero pass +
fsync) before unlinking, so a local attacker reading raw sectors cannot
recover the partial plaintext from the slack (Fix-1.N).
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
_WIPE_BLOCK_BYTES: int = 64 * 1024


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
        try:
            Path(tmp_path).replace(path)
        except OSError as exc:
            import errno

            if exc.errno == errno.EXDEV:
                msg = (
                    f"destination '{path}' lives on a different filesystem "
                    f"than the temp directory '{tmp_path.parent}'; atomic "
                    "rename is impossible across volumes. Move the temp "
                    "target (via TMPDIR / TMP) or point the output inside "
                    "the same filesystem as the source."
                )
                raise OSError(errno.EXDEV, msg) from exc
            raise
        _fsync_dir(path.parent)
    except (KeyboardInterrupt, Exception):
        # Close then wipe-unlink the temp file. On the decrypt path the
        # temp may carry partial plaintext, so a plain unlink would leave
        # that plaintext on disk until the blocks are overwritten by
        # unrelated allocations. We overwrite with zeros + fsync before
        # the unlink (Fix-1.N). Best-effort: swallow every OSError so we
        # do not mask the original exception.
        with suppress(OSError):
            tmp.close()
        _best_effort_wipe_and_unlink(tmp_path)
        raise


def _best_effort_wipe_and_unlink(path: Path) -> None:
    """Overwrite ``path`` with zeros, fsync, then unlink.

    Every filesystem / OS error is swallowed: the caller is already in an
    exception path (rollback after Ctrl+C or a crypto failure) and must
    not be masked by a secondary error during cleanup. Worst case the
    temp file survives with its partial content — same outcome as the
    pre-Fix-1.N behaviour, never worse.
    """
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    if size > 0:
        try:
            with path.open("r+b", buffering=0) as wipe_fp:
                remaining = size
                while remaining > 0:
                    block = min(_WIPE_BLOCK_BYTES, remaining)
                    wipe_fp.write(b"\x00" * block)
                    remaining -= block
                wipe_fp.flush()
                with suppress(OSError):
                    os.fsync(wipe_fp.fileno())
        except OSError:
            pass
    with suppress(OSError):
        path.unlink(missing_ok=True)


def _fsync_dir(directory: Path) -> None:
    """Flush directory metadata so the rename is durable on POSIX.

    On Windows, directories cannot be opened with ``os.open``; the rename is
    durable once :func:`os.replace` returns, so this is a no-op.
    """
    if os.name != "posix":
        return
    _fsync_dir_posix(directory)  # pragma: no cover -- POSIX-only branch


def _fsync_dir_posix(directory: Path) -> None:  # pragma: no cover -- POSIX only
    """POSIX-specific directory fsync.

    Extracted into its own function so the coverage pragma sits once at
    the function level instead of scattered across every statement. The
    ``os.O_DIRECTORY`` flag is only defined on POSIX; ``getattr`` avoids
    a static attribute lookup that mypy on Windows would flag.
    """
    o_directory: int = getattr(os, "O_DIRECTORY", 0)
    fd = os.open(str(directory), o_directory)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
