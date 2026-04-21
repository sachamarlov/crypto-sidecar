"""Unit tests for :mod:`guardiabox.core.operations`.

PBKDF2 dominates run-time here (≥ 600 000 iterations per derivation). Tests
are written to minimise derivations: most reuse a single encrypt+decrypt
cycle per scenario.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from guardiabox.core.constants import DEFAULT_CHUNK_BYTES, ENCRYPTED_SUFFIX
from guardiabox.core.exceptions import (
    CorruptedContainerError,
    DecryptionError,
    PathTraversalError,
    WeakPasswordError,
)
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.core.operations import (
    decrypt_file,
    decrypt_message,
    encrypt_file,
    encrypt_message,
)

STRONG_PASSWORD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret


@pytest.mark.parametrize(
    "size",
    [
        0,
        1,
        DEFAULT_CHUNK_BYTES - 1,
        DEFAULT_CHUNK_BYTES,
        DEFAULT_CHUNK_BYTES + 1,
        DEFAULT_CHUNK_BYTES * 2 + 5,
    ],
)
def test_roundtrip_pbkdf2(tmp_path: Path, size: int) -> None:
    source = tmp_path / "plain.bin"
    data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    source.write_bytes(data)

    enc = encrypt_file(source, STRONG_PASSWORD, kdf=Pbkdf2Kdf())
    assert enc.name == source.name + ENCRYPTED_SUFFIX

    dec = decrypt_file(enc, STRONG_PASSWORD)
    assert dec.read_bytes() == data


def test_original_left_untouched(tmp_path: Path) -> None:
    source = tmp_path / "plain.bin"
    data = b"unchanged" * 1024
    source.write_bytes(data)
    mtime = source.stat().st_mtime

    encrypt_file(source, STRONG_PASSWORD, kdf=Pbkdf2Kdf())

    assert source.read_bytes() == data
    assert source.stat().st_mtime == mtime


def test_encrypted_header_starts_with_magic(tmp_path: Path) -> None:
    source = tmp_path / "plain.bin"
    source.write_bytes(b"data")
    enc = encrypt_file(source, STRONG_PASSWORD, kdf=Pbkdf2Kdf())
    assert enc.read_bytes().startswith(b"GBOX")


def test_weak_password_refused_before_write(tmp_path: Path) -> None:
    source = tmp_path / "plain.bin"
    source.write_bytes(b"data")
    dest = source.with_name(source.name + ENCRYPTED_SUFFIX)
    with pytest.raises(WeakPasswordError):
        encrypt_file(source, "weak")
    assert not dest.exists()


def test_wrong_password_rejected(tmp_path: Path) -> None:
    source = tmp_path / "plain.bin"
    source.write_bytes(b"secret data")
    enc = encrypt_file(source, STRONG_PASSWORD, kdf=Pbkdf2Kdf())
    with pytest.raises(DecryptionError):
        decrypt_file(enc, "Another_But_Strong_Password_42!")


def test_tampered_ciphertext_rejected(tmp_path: Path) -> None:
    source = tmp_path / "plain.bin"
    source.write_bytes(b"secret data")
    enc = encrypt_file(source, STRONG_PASSWORD, kdf=Pbkdf2Kdf())
    # Flip one byte in the ciphertext region (skip the 40-byte PBKDF2 header).
    raw = bytearray(enc.read_bytes())
    raw[-1] ^= 0x01
    enc.write_bytes(bytes(raw))
    with pytest.raises(DecryptionError):
        decrypt_file(enc, STRONG_PASSWORD, dest=tmp_path / "out.bin")


def test_truncated_stream_rejected(tmp_path: Path) -> None:
    source = tmp_path / "plain.bin"
    source.write_bytes(b"x" * (DEFAULT_CHUNK_BYTES * 2 + 5))
    enc = encrypt_file(source, STRONG_PASSWORD, kdf=Pbkdf2Kdf())
    # Remove the last chunk entirely to simulate a truncation attack.
    raw = enc.read_bytes()
    enc.write_bytes(raw[: DEFAULT_CHUNK_BYTES * 2])  # strip final chunk
    with pytest.raises((DecryptionError, CorruptedContainerError)):
        decrypt_file(enc, STRONG_PASSWORD, dest=tmp_path / "out.bin")


def test_path_traversal_rejected_for_dest_outside_source_parent(
    tmp_path: Path,
) -> None:
    source = tmp_path / "dir" / "plain.bin"
    source.parent.mkdir()
    source.write_bytes(b"data")
    bad_dest = tmp_path / "other.crypt"
    with pytest.raises(PathTraversalError):
        encrypt_file(source, STRONG_PASSWORD, kdf=Pbkdf2Kdf(), dest=bad_dest)


def test_message_roundtrip(tmp_path: Path) -> None:
    dest = tmp_path / "note.crypt"
    encrypt_message(b"the magic words", STRONG_PASSWORD, kdf=Pbkdf2Kdf(), dest=dest)
    assert decrypt_message(dest, STRONG_PASSWORD) == b"the magic words"


def test_empty_message_roundtrip(tmp_path: Path) -> None:
    dest = tmp_path / "empty.crypt"
    encrypt_message(b"", STRONG_PASSWORD, kdf=Pbkdf2Kdf(), dest=dest)
    assert decrypt_message(dest, STRONG_PASSWORD) == b""


def test_large_message_roundtrip(tmp_path: Path) -> None:
    payload = b"Y" * (DEFAULT_CHUNK_BYTES * 3 + 11)
    dest = tmp_path / "big.crypt"
    encrypt_message(payload, STRONG_PASSWORD, kdf=Pbkdf2Kdf(), dest=dest)
    assert decrypt_message(dest, STRONG_PASSWORD) == payload


@pytest.mark.slow
def test_argon2id_roundtrip(tmp_path: Path) -> None:
    source = tmp_path / "plain.bin"
    source.write_bytes(b"secret" * 1024)
    enc = encrypt_file(source, STRONG_PASSWORD, kdf=Argon2idKdf())
    dec = decrypt_file(enc, STRONG_PASSWORD)
    assert dec.read_bytes() == source.read_bytes()


def test_default_decrypt_dest_preserves_original_name(tmp_path: Path) -> None:
    source = tmp_path / "report.pdf"
    source.write_bytes(b"pretend-pdf-bytes")
    enc = encrypt_file(source, STRONG_PASSWORD, kdf=Pbkdf2Kdf())
    assert enc.name == "report.pdf.crypt"
    dec = decrypt_file(enc, STRONG_PASSWORD)
    assert dec.name == "report.pdf.decrypt"


def test_explicit_decrypt_dest_respected(tmp_path: Path) -> None:
    source = tmp_path / "in.bin"
    source.write_bytes(b"data")
    enc = encrypt_file(source, STRONG_PASSWORD, kdf=Pbkdf2Kdf())
    out = tmp_path / "out.bin"
    dec = decrypt_file(enc, STRONG_PASSWORD, dest=out)
    assert dec == out.resolve()
    assert out.read_bytes() == b"data"


def test_empty_ciphertext_stream_raises(tmp_path: Path) -> None:
    """Header-only container with zero ciphertext must fail loudly."""
    source = tmp_path / "plain.bin"
    source.write_bytes(b"data")
    enc = encrypt_file(source, STRONG_PASSWORD, kdf=Pbkdf2Kdf())
    raw = enc.read_bytes()
    # Keep the header (48 bytes cover PBKDF2) and drop all chunks.
    # The header layout gives us a cheap lower bound: magic(4) + prefix(4) +
    # kdf_params_len (at least 4) + salt(16) + nonce(12) = 40 min bytes.
    enc.write_bytes(raw[:40])
    with pytest.raises((CorruptedContainerError, DecryptionError)):
        decrypt_file(enc, STRONG_PASSWORD, dest=tmp_path / "out.bin")


def test_truncated_final_chunk_smaller_than_tag(tmp_path: Path) -> None:
    source = tmp_path / "plain.bin"
    source.write_bytes(b"data" * 10)
    enc = encrypt_file(source, STRONG_PASSWORD, kdf=Pbkdf2Kdf())
    raw = enc.read_bytes()
    # Truncate so the ciphertext part has fewer than 16 bytes after the header.
    enc.write_bytes(raw[:-50] + b"\x00" * 5)
    with pytest.raises((CorruptedContainerError, DecryptionError)):
        decrypt_file(enc, STRONG_PASSWORD, dest=tmp_path / "out.bin")


def test_decrypt_default_dest_without_crypt_suffix(tmp_path: Path) -> None:
    """A ``.crypt``-less source must still produce a ``.decrypt`` file."""
    source = tmp_path / "plain.bin"
    source.write_bytes(b"secret")
    enc_default = encrypt_file(source, STRONG_PASSWORD, kdf=Pbkdf2Kdf())
    # Rename the encrypted container so its suffix is no longer ``.crypt``.
    renamed = tmp_path / "renamed_container"
    enc_default.rename(renamed)
    dec = decrypt_file(renamed, STRONG_PASSWORD)
    assert dec.name.endswith(".decrypt")
    assert dec.read_bytes() == b"secret"


def test_decrypt_message_wrong_password_raises_and_logs(tmp_path: Path) -> None:
    """Cover the warning-log path on decrypt_message failure."""
    dest = tmp_path / "msg.crypt"
    encrypt_message(b"payload", STRONG_PASSWORD, kdf=Pbkdf2Kdf(), dest=dest)
    with pytest.raises(DecryptionError):
        decrypt_message(dest, "Another_But_Strong_Password_42!")  # pragma: allowlist secret


@pytest.mark.slow
def test_roundtrip_10_mib(tmp_path: Path) -> None:
    """Full encrypt + decrypt of a 10 MiB random payload.

    Runs the streaming pipeline across ~160 chunks at DEFAULT_CHUNK_BYTES.
    Two KDF derivations are expensive but not prohibitive; this test carries
    the ``slow`` marker so the fast suite stays under 30 s.
    """
    import secrets as _secrets

    source = tmp_path / "big.bin"
    payload = _secrets.token_bytes(10 * 1024 * 1024)
    source.write_bytes(payload)

    enc = encrypt_file(source, STRONG_PASSWORD, kdf=Pbkdf2Kdf())
    dec = decrypt_file(enc, STRONG_PASSWORD)
    assert dec.read_bytes() == payload
