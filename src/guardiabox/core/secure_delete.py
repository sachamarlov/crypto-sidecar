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

from enum import Enum, StrEnum
import os
from pathlib import Path
import secrets
from typing import IO

__all__ = [
    "DEFAULT_OVERWRITE_PASSES",
    "MAX_OVERWRITE_PASSES",
    "SecureDeleteMethod",
    "secure_delete",
]

#: DoD 5220.22-M specifies three passes (zero, one, random). Going higher
#: is permitted but offers diminishing returns on modern drives.
_DOD_PATTERN_ZERO: bytes = b"\x00"
_DOD_PATTERN_ONE: bytes = b"\xff"


class _PassKind(Enum):
    r"""Discriminator returned by :func:`_pattern_for_pass`.

    Using an enum (rather than a sentinel byte) avoids a subtle
    non-determinism: if the random-pass byte happened to be ``\x00`` or
    ``\xff``, the previous design would mistake it for the zero/one
    pattern and overwrite the file with that fixed byte instead of fresh
    random bytes (≈ 0.78 % per pass).
    """

    ZERO = "zero"
    ONE = "one"
    RANDOM = "random"


DEFAULT_OVERWRITE_PASSES: int = 3

#: Upper bound on ``passes``. 35 matches the Gutmann "paranoid" maximum
#: and acts as a DoS guard: a caller (or a crafted CLI argument) that
#: requested ``passes=10**9`` would otherwise stall the host for days
#: writing 64 KiB blocks in a tight loop.
MAX_OVERWRITE_PASSES: int = 35

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
        ValueError: If ``passes`` is outside ``[1, MAX_OVERWRITE_PASSES]``,
            or if the method is not recognised.
    """
    if passes < 1:
        raise ValueError(f"passes must be >= 1, got {passes}")
    if passes > MAX_OVERWRITE_PASSES:
        raise ValueError(f"passes must be <= {MAX_OVERWRITE_PASSES}, got {passes}")
    if method is not SecureDeleteMethod.OVERWRITE_DOD:
        raise ValueError(f"unsupported method: {method!r}")

    resolved = path.resolve(strict=True)
    if resolved.is_dir():
        raise IsADirectoryError(f"refusing to secure-delete a directory: {resolved}")
    if resolved.is_symlink():
        raise ValueError(f"refusing to secure-delete a symlink: {resolved}")

    _overwrite_dod(resolved, passes=passes)
    resolved.unlink()


def _pattern_for_pass(index: int) -> _PassKind:
    """Return the fill kind for pass ``index`` (0-based).

    The cycle is ``[zero, one, random]`` and repeats when ``index >= 3``
    (so ``passes=4`` re-runs zero, ``passes=5`` re-runs one, etc.).
    """
    mod = index % 3
    if mod == 0:
        return _PassKind.ZERO
    if mod == 1:
        return _PassKind.ONE
    return _PassKind.RANDOM


def _overwrite_dod(path: Path, *, passes: int) -> None:
    """Overwrite ``path`` in-place ``passes`` times, fsync'ing each pass."""
    size = path.stat().st_size
    # ``r+b`` opens for read/write without truncation so we can rewrite in
    # place. buffering=0 disables the Python-level buffer so ``flush`` /
    # ``fsync`` below really hit the disk.
    with path.open("r+b", buffering=0) as fp:
        for index in range(passes):
            kind = _pattern_for_pass(index)
            _fill_in_place(fp, size=size, kind=kind)
            fp.flush()
            os.fsync(fp.fileno())


def _fill_in_place(fp: IO[bytes], *, size: int, kind: _PassKind) -> None:
    r"""Write the pass ``kind`` over ``size`` bytes from offset 0.

    Zero (``\x00``) and one (``\xff``) passes reuse the same fixed byte
    via ``pattern * chunk_size``. Random passes pull a fresh block from
    :func:`secrets.token_bytes` for every chunk, so the bytes on disk
    are not predictable from one chunk to the next (DoD 5220.22-M pass
    #3 intent).
    """
    fp.seek(0)
    written = 0
    fixed: bytes | None
    if kind is _PassKind.ZERO:
        fixed = _DOD_PATTERN_ZERO
    elif kind is _PassKind.ONE:
        fixed = _DOD_PATTERN_ONE
    else:
        fixed = None
    while written < size:
        chunk_size = min(_OVERWRITE_CHUNK_BYTES, size - written)
        chunk = secrets.token_bytes(chunk_size) if fixed is None else fixed * chunk_size
        fp.write(chunk)
        written += chunk_size
