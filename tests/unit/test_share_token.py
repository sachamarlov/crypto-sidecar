"""Unit tests for :mod:`guardiabox.core.share_token` (T-003.03)."""

from __future__ import annotations

import struct
from uuid import UUID, uuid4

import pytest

from guardiabox.core.exceptions import (
    CorruptedContainerError,
    InvalidContainerError,
    UnsupportedVersionError,
)
from guardiabox.core.share_token import (
    MAX_WRAPPED_DEK_BYTES,
    PERMISSION_READ,
    PERMISSION_RESHARE,
    SHARE_TOKEN_MAGIC,
    SHARE_TOKEN_VERSION,
    SIGNATURE_BYTES,
    ShareTokenHeader,
    build_payload_for_signing,
    read_token,
    write_token,
)


def _sample_header(*, dek_size: int = 512) -> ShareTokenHeader:
    return ShareTokenHeader(
        sender_user_id=UUID("11111111-2222-3333-4444-555555555555"),
        recipient_user_id=UUID("99999999-8888-7777-6666-555555555555"),
        content_sha256=b"\x33" * 32,
        wrapped_dek=b"\xab" * dek_size,
        expires_at=1_900_000_000,
        permission_flags=PERMISSION_READ,
    )


def _sample_signature() -> bytes:
    return b"\xee" * SIGNATURE_BYTES


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_write_then_read_returns_identical_fields() -> None:
    header = _sample_header()
    ciphertext = b"\x77" * 1024
    sig = _sample_signature()
    blob = write_token(header=header, embedded_ciphertext=ciphertext, signature=sig)

    parsed = read_token(blob)

    assert parsed.header == header
    assert parsed.embedded_ciphertext == ciphertext
    assert parsed.signature == sig
    assert parsed.payload_bytes == blob[:-SIGNATURE_BYTES]


def test_write_token_starts_with_magic_and_version() -> None:
    blob = write_token(
        header=_sample_header(),
        embedded_ciphertext=b"x",
        signature=_sample_signature(),
    )
    assert blob[:4] == SHARE_TOKEN_MAGIC
    assert blob[4] == SHARE_TOKEN_VERSION


def test_payload_for_signing_matches_blob_minus_signature() -> None:
    header = _sample_header()
    ciphertext = b"\x42" * 100
    sig = _sample_signature()
    blob = write_token(header=header, embedded_ciphertext=ciphertext, signature=sig)
    payload_for_signing = build_payload_for_signing(header, ciphertext)
    assert payload_for_signing == blob[:-SIGNATURE_BYTES]


def test_zero_length_embedded_ciphertext_roundtrip() -> None:
    blob = write_token(
        header=_sample_header(),
        embedded_ciphertext=b"",
        signature=_sample_signature(),
    )
    parsed = read_token(blob)
    assert parsed.embedded_ciphertext == b""


def test_permission_flags_resharing_bit() -> None:
    header = ShareTokenHeader(
        sender_user_id=uuid4(),
        recipient_user_id=uuid4(),
        content_sha256=b"\x00" * 32,
        wrapped_dek=b"\x01" * 512,
        expires_at=0,  # never expires
        permission_flags=PERMISSION_READ | PERMISSION_RESHARE,
    )
    blob = write_token(header=header, embedded_ciphertext=b"x", signature=_sample_signature())
    parsed = read_token(blob)
    assert parsed.header.permission_flags & PERMISSION_RESHARE
    assert parsed.header.permission_flags & PERMISSION_READ


# ---------------------------------------------------------------------------
# Invariants enforced by ShareTokenHeader.__post_init__
# ---------------------------------------------------------------------------


def test_header_rejects_short_sha256() -> None:
    with pytest.raises(ValueError, match=r"content_sha256 must be 32 bytes"):
        ShareTokenHeader(
            sender_user_id=uuid4(),
            recipient_user_id=uuid4(),
            content_sha256=b"\x00" * 31,
            wrapped_dek=b"\x00" * 512,
            expires_at=0,
            permission_flags=0,
        )


def test_header_rejects_oversized_dek() -> None:
    with pytest.raises(ValueError, match=r"wrapped_dek length"):
        ShareTokenHeader(
            sender_user_id=uuid4(),
            recipient_user_id=uuid4(),
            content_sha256=b"\x00" * 32,
            wrapped_dek=b"\x00" * (MAX_WRAPPED_DEK_BYTES + 1),
            expires_at=0,
            permission_flags=0,
        )


def test_header_rejects_negative_expires_at() -> None:
    with pytest.raises(ValueError, match=r"expires_at"):
        ShareTokenHeader(
            sender_user_id=uuid4(),
            recipient_user_id=uuid4(),
            content_sha256=b"\x00" * 32,
            wrapped_dek=b"\x00" * 512,
            expires_at=-1,
            permission_flags=0,
        )


def test_header_rejects_oversized_permission_flags() -> None:
    with pytest.raises(ValueError, match=r"permission_flags"):
        ShareTokenHeader(
            sender_user_id=uuid4(),
            recipient_user_id=uuid4(),
            content_sha256=b"\x00" * 32,
            wrapped_dek=b"\x00" * 512,
            expires_at=0,
            permission_flags=2**33,
        )


# ---------------------------------------------------------------------------
# write_token validates signature length
# ---------------------------------------------------------------------------


def test_write_token_rejects_wrong_signature_length() -> None:
    with pytest.raises(ValueError, match=r"signature must be"):
        write_token(
            header=_sample_header(),
            embedded_ciphertext=b"x",
            signature=b"\x00" * 100,
        )


# ---------------------------------------------------------------------------
# read_token defensive parsing
# ---------------------------------------------------------------------------


def test_read_token_rejects_short_blob() -> None:
    with pytest.raises(CorruptedContainerError, match=r"too short"):
        read_token(b"\x00" * 50)


def test_read_token_rejects_wrong_magic() -> None:
    blob = write_token(
        header=_sample_header(),
        embedded_ciphertext=b"x",
        signature=_sample_signature(),
    )
    tampered = b"XXXX" + blob[4:]  # magic flipped
    with pytest.raises(InvalidContainerError, match=r"magic mismatch"):
        read_token(tampered)


def test_read_token_rejects_unsupported_version() -> None:
    blob = bytearray(
        write_token(
            header=_sample_header(),
            embedded_ciphertext=b"x",
            signature=_sample_signature(),
        )
    )
    blob[4] = 0xFE  # version byte is offset 4
    with pytest.raises(UnsupportedVersionError, match=r"version 254"):
        read_token(bytes(blob))


def test_read_token_rejects_oversized_dek_length() -> None:
    """A crafted token claiming dek_len > MAX is rejected without
    allocating the implied buffer."""
    # Build a hand-crafted blob: real prefix but dek_len patched.
    real = write_token(
        header=_sample_header(),
        embedded_ciphertext=b"",
        signature=_sample_signature(),
    )
    blob = bytearray(real)
    # dek_len lives at offset 69 (4+1+16+16+32) as uint16 big-endian.
    bogus_len = MAX_WRAPPED_DEK_BYTES + 1
    blob[69:71] = struct.pack("!H", bogus_len)
    with pytest.raises(CorruptedContainerError, match=r"exceeds maximum"):
        read_token(bytes(blob))


def test_read_token_rejects_dek_overruning_buffer() -> None:
    """dek_len <= cap but pointing past end of buffer."""
    header = _sample_header(dek_size=1)
    blob = bytearray(
        write_token(
            header=header,
            embedded_ciphertext=b"",
            signature=_sample_signature(),
        )
    )
    # Patch dek_len to claim 200 bytes when only 1 byte is present.
    blob[69:71] = struct.pack("!H", 200)
    with pytest.raises(CorruptedContainerError, match=r"truncated"):
        read_token(bytes(blob))


def test_read_token_returns_signed_payload_bytes() -> None:
    """payload_bytes must be exactly what RsaSign.verify will see."""
    header = _sample_header()
    ciphertext = b"\x12" * 256
    sig = _sample_signature()
    blob = write_token(header=header, embedded_ciphertext=ciphertext, signature=sig)
    parsed = read_token(blob)
    expected_payload = build_payload_for_signing(header, ciphertext)
    assert parsed.payload_bytes == expected_payload
