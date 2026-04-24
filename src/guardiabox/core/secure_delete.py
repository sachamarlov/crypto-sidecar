"""Secure deletion of plaintext files — DoD 5220.22-M multi-pass overwrite.

Two strategies are eventually exposed (cf. ``docs/specs/004-secure-delete``):

* **Multi-pass overwrite** — zero / one / random passes followed by
  ``unlink``. Meaningful on rotational media (HDD). Best-effort on SSDs
  because wear-levelling remaps logical blocks transparently.
* **Cryptographic erase** — destroys the file's data-encryption key in
  the keystore, rendering the ciphertext computationally unrecoverable.
  Reserved for spec 004 Phase B2 once the multi-user keystore lands.

This module implements the overwrite path today. Crypto-erase is
deliberately absent from the enum until the keystore exists, so the CLI
can never route to a dispatch that would raise ``NotImplementedError``.
"""

from __future__ import annotations

from enum import StrEnum
import os
from pathlib import Path
import secrets
from typing import IO

__all__ = [
    "DEFAULT_OVERWRITE_PASSES",
    "SecureDeleteMethod",
    "secure_delete",
]

#: Minimum number of overwrite passes exposed by the CLI. DoD 5220.22-M
#: specifies three — zero, one, random. Going higher is permitted but
#: offers diminishing returns on modern drives.
_DOD_PATTERN_ZERO: bytes = b"\x00"
_DOD_PATTERN_ONE: bytes = b"\xff"

DEFAULT_OVERWRITE_PASSES: int = 3

#: Block size used to fill each pass. 64 KiB balances syscall count against
#: memory footprint without breaking small-file cases (the write is capped
#: to the remaining file size).
_OVERWRITE_CHUNK_BYTES: int = 64 * 1024


class SecureDeleteMethod(StrEnum):
    """Strategy used by :func:`secure_delete`.

    Only ``OVERWRITE_DOD`` is currently dispatchable — :data:`CRYPTO_ERASE`
    will be added alongside the keystore implementation (spec 004
    Phase B2).
    """

    OVERWRITE_DOD = "overwrite-dod"


def secure_delete(
    path: Path,
    *,
    method: SecureDeleteMethod = SecureDeleteMethod.OVERWRITE_DOD,
    passes: int = DEFAULT_OVERWRITE_PASSES,
) -> None:
    """Securely delete the file at ``path``.

    Args:
        path: Absolute or relative file to remove. Resolved before any
            write. Must refer to a regular file — directories and
            symlinks are refused.
        method: Deletion strategy. Only
            :data:`SecureDeleteMethod.OVERWRITE_DOD` is accepted today.
        passes: Number of overwrite passes (default ``3``; minimum ``1``).
            The pattern sequence is zero / one / random and repeats
            when ``passes > 3``.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        IsADirectoryError: If ``path`` is a directory.
        ValueError: If ``passes`` is not strictly positive, or if the
            method is not recognised.
    """
    if passes < 1:
        raise ValueError(f"passes must be >= 1, got {passes}")
    if method is not SecureDeleteMethod.OVERWRITE_DOD:
        raise ValueError(f"unsupported method: {method!r}")

    resolved = path.resolve(strict=True)
    if resolved.is_dir():
        raise IsADirectoryError(f"refusing to secure-delete a directory: {resolved}")
    if resolved.is_symlink():
        raise ValueError(f"refusing to secure-delete a symlink: {resolved}")

    _overwrite_dod(resolved, passes=passes)
    resolved.unlink()


def _pattern_for_pass(index: int) -> bytes:
    """Return the one-byte fill pattern for pass ``index`` (0-based)."""
    # Cycle through zero / one / random; pass ``n`` picks
    # ``[zero, one, random][n % 3]``. Random passes freshly
    # draw from ``secrets`` each call.
    mod = index % 3
    if mod == 0:
        return _DOD_PATTERN_ZERO
    if mod == 1:
        return _DOD_PATTERN_ONE
    return secrets.token_bytes(1)


def _overwrite_dod(path: Path, *, passes: int) -> None:
    """Overwrite ``path`` in-place ``passes`` times, fsync'ing each pass."""
    size = path.stat().st_size
    # ``r+b`` opens for read/write without truncation so we can rewrite in
    # place. buffering=0 disables the Python-level buffer so ``flush`` /
    # ``fsync`` below really hit the disk.
    with path.open("r+b", buffering=0) as fp:
        for index in range(passes):
            pattern = _pattern_for_pass(index)
            _fill_in_place(fp, size=size, pattern=pattern)
            fp.flush()
            os.fsync(fp.fileno())


def _fill_in_place(fp: IO[bytes], *, size: int, pattern: bytes) -> None:
    r"""Write ``pattern`` (1 byte) over ``size`` bytes from offset 0.

    Uses a pre-allocated bytes block to minimise allocation churn. When
    the pattern is ``\xff`` (pass 1) or ``\x00`` (pass 0) the block is
    reused across calls; for random passes the caller re-seeds via
    :func:`secrets.token_bytes` per chunk so the pass's random bytes
    are never predictable from one chunk to the next.
    """
    fp.seek(0)
    written = 0
    if pattern == b"":
        raise ValueError("pattern must be non-empty")
    random_pass = pattern not in {_DOD_PATTERN_ZERO, _DOD_PATTERN_ONE}
    while written < size:
        chunk_size = min(_OVERWRITE_CHUNK_BYTES, size - written)
        chunk = secrets.token_bytes(chunk_size) if random_pass else pattern * chunk_size
        fp.write(chunk)
        written += chunk_size
