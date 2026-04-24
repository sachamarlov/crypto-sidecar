"""Anti-partial-output discipline tests.

Covers spec 002 T-002.10: a decryption that fails mid-stream must not
leave a partial ``.decrypt`` file on disk. The guarantee is implemented
by :func:`guardiabox.fileio.atomic.atomic_writer` which only renames the
temp file onto the destination after a clean close.

We exercise the guarantee by constructing a ``.crypt`` file whose first
chunk verifies correctly but whose next chunk has been corrupted: the
decoder yields the first plaintext chunk, attempts to authenticate the
second, fails, and the atomic writer's except path must tear down the
temp file before re-raising.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from guardiabox.core.constants import DEFAULT_CHUNK_BYTES
from guardiabox.core.exceptions import DecryptionError, InvalidContainerError
from guardiabox.core.kdf import Pbkdf2Kdf
from guardiabox.core.operations import decrypt_file, encrypt_file

STRONG_PASSWORD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret


def test_no_decrypt_file_when_mid_stream_chunk_is_corrupted(tmp_path: Path) -> None:
    """Corrupt the second chunk's tag → decrypt aborts → no .decrypt remains."""
    source = tmp_path / "multi.bin"
    source.write_bytes(b"A" * (DEFAULT_CHUNK_BYTES * 2 + 128))
    crypt = encrypt_file(source, STRONG_PASSWORD, root=tmp_path, kdf=Pbkdf2Kdf())

    raw = bytearray(crypt.read_bytes())
    second_chunk_offset = 40 + DEFAULT_CHUNK_BYTES + 16
    raw[second_chunk_offset + 10] ^= 0x80
    crypt.write_bytes(bytes(raw))

    dest = tmp_path / "multi.out"
    with pytest.raises(DecryptionError):
        decrypt_file(crypt, STRONG_PASSWORD, root=tmp_path, dest=dest)

    assert not dest.exists(), (
        "atomic_writer leaked a partial plaintext file after mid-stream failure"
    )
    leftovers = [p for p in tmp_path.iterdir() if p.suffix == ".tmp.gbox"]
    assert leftovers == []


def test_no_decrypt_file_when_header_is_corrupted(tmp_path: Path) -> None:
    """Corrupt the magic bytes → parse fails → no .decrypt created.

    Header corruption is pre-KDF so it surfaces as InvalidContainerError
    (exit 65), not DecryptionError (exit 2) — that distinction is fine
    because the attacker can trivially see the first four bytes anyway.
    """
    source = tmp_path / "small.bin"
    source.write_bytes(b"hello")
    crypt = encrypt_file(source, STRONG_PASSWORD, root=tmp_path, kdf=Pbkdf2Kdf())

    raw = bytearray(crypt.read_bytes())
    raw[0] ^= 0xFF
    crypt.write_bytes(bytes(raw))

    dest = tmp_path / "out.bin"
    with pytest.raises(InvalidContainerError):
        decrypt_file(crypt, STRONG_PASSWORD, root=tmp_path, dest=dest)

    assert not dest.exists()


def test_wrong_password_leaves_no_decrypt_file(tmp_path: Path) -> None:
    source = tmp_path / "small.bin"
    source.write_bytes(b"secret")
    crypt = encrypt_file(source, STRONG_PASSWORD, root=tmp_path, kdf=Pbkdf2Kdf())

    dest = tmp_path / "out.bin"
    with pytest.raises(DecryptionError):
        decrypt_file(
            crypt,
            "Another_Strong_But_Wrong_42!",  # pragma: allowlist secret
            root=tmp_path,
            dest=dest,
        )

    assert not dest.exists()
    leftovers = [p for p in tmp_path.iterdir() if p.suffix == ".tmp.gbox"]
    assert leftovers == []
