"""``.gbox-share`` v1 binary container — spec 003 share-token format (T-003.03).

On-disk layout
--------------

::

    offset    bytes   field
    ─────────────────────────────────────────────────────────────
    0         4       magic = b"GBSH"
    4         1       version = 0x01
    5         16      sender_user_id (UUIDv4 bytes)
    21        16      recipient_user_id (UUIDv4 bytes)
    37        32      content_sha256 (SHA-256 of the embedded .crypt)
    69        2       wrapped_dek_length (uint16 BE)
    71        N       wrapped_dek (RSA-OAEP-SHA256, recipient's pubkey)
    71+N      8       expires_at (uint64 BE Unix epoch seconds; 0 = never)
    79+N      4       permission_flags (uint32 BE; bit 0 = read, bit 1 = re-share)
    83+N      *       embedded ciphertext (the .crypt payload bytes)
    EOF-512   512     RSA-PSS-SHA256 signature over EVERYTHING preceding

The signature occupies the last :data:`SIGNATURE_BYTES` bytes; the
*payload* (every byte the signature authenticates) is the file content
minus that suffix. :func:`read_token` returns ``payload_bytes`` so the
caller can hand it to :func:`guardiabox.core.rsa.RsaSign.verify` before
doing anything else with the token. accept_share **must** verify before
any unwrap or decrypt — this is the anti-oracle discipline (ADR-0015)
applied to share tokens.

Defensive parsing
-----------------

The reader validates the magic, version, and ``wrapped_dek_length`` cap
**before** copying any variable-length region. A crafted token claiming
``wrapped_dek_length = 65535`` is rejected as
:class:`~guardiabox.core.exceptions.CorruptedContainerError` without
allocating the implied buffer first. The fixed signature suffix means a
truncated file fails magic / length checks, never reaches the
embedded-ciphertext branch.

Version policy
--------------

A version bump (``0x02``) is required for any of:

* Layout reorder, field width change, or field add/remove.
* Signature length change (e.g. 256 bytes for 2048-bit keys).
* New permission bits with non-default semantics.

Adding a permission bit at an unused position keeps version 0x01
compatible (the reader masks unknown bits at use time).
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Final
from uuid import UUID

from guardiabox.core.exceptions import (
    CorruptedContainerError,
    InvalidContainerError,
    UnsupportedVersionError,
)

__all__ = [
    "MAX_WRAPPED_DEK_BYTES",
    "PERMISSION_READ",
    "PERMISSION_RESHARE",
    "SHARE_TOKEN_MAGIC",
    "SHARE_TOKEN_VERSION",
    "SIGNATURE_BYTES",
    "ParsedShareToken",
    "ShareTokenHeader",
    "read_token",
    "write_token",
]


SHARE_TOKEN_MAGIC: Final[bytes] = b"GBSH"
"""Magic prefix on every ``.gbox-share`` v1 file."""

SHARE_TOKEN_VERSION: Final[int] = 1
"""Current ``.gbox-share`` format version."""

MAX_WRAPPED_DEK_BYTES: Final[int] = 1024
"""Cap on ``wrapped_dek_length``. Two times the 4096-bit RSA modulus
(512 bytes). Anything larger is treated as an adversarial header crafted
to force a large allocation before further validation."""

SIGNATURE_BYTES: Final[int] = 512
"""RSA-PSS signature length for 4096-bit keys (production keystore default)."""

PERMISSION_READ: Final[int] = 1 << 0
"""Bit 0 — recipient may decrypt the embedded ciphertext."""

PERMISSION_RESHARE: Final[int] = 1 << 1
"""Bit 1 — recipient may re-share the file under their own keypair."""


# Pre-compiled struct formats. ``!`` forces big-endian network order.
_HEADER_PREFIX = struct.Struct("!4sB16s16s32sH")
"""magic(4) | version(1) | sender(16) | recipient(16) | sha256(32) | dek_len(2)."""

_FOOTER_FIELDS = struct.Struct("!QI")
"""expires_at(8) | permission_flags(4)."""

_HEADER_PREFIX_SIZE: Final[int] = _HEADER_PREFIX.size
_FOOTER_SIZE: Final[int] = _FOOTER_FIELDS.size
_MIN_TOKEN_BYTES: Final[int] = _HEADER_PREFIX_SIZE + _FOOTER_SIZE + SIGNATURE_BYTES


@dataclass(frozen=True, slots=True)
class ShareTokenHeader:
    """Logical header of a ``.gbox-share`` token.

    Carries every field except the embedded ciphertext and the trailing
    signature. Field invariants are enforced in ``__post_init__``.
    """

    sender_user_id: UUID
    recipient_user_id: UUID
    content_sha256: bytes
    wrapped_dek: bytes
    expires_at: int  # Unix epoch seconds; 0 = never expires.
    permission_flags: int

    def __post_init__(self) -> None:
        if len(self.content_sha256) != 32:
            raise ValueError(f"content_sha256 must be 32 bytes, got {len(self.content_sha256)}")
        if len(self.wrapped_dek) > MAX_WRAPPED_DEK_BYTES:
            raise ValueError(
                f"wrapped_dek length {len(self.wrapped_dek)} exceeds "
                f"MAX_WRAPPED_DEK_BYTES={MAX_WRAPPED_DEK_BYTES}"
            )
        if self.expires_at < 0 or self.expires_at.bit_length() > 64:
            raise ValueError(f"expires_at {self.expires_at} out of uint64 range")
        if self.permission_flags < 0 or self.permission_flags.bit_length() > 32:
            raise ValueError(f"permission_flags {self.permission_flags} out of uint32 range")


@dataclass(frozen=True, slots=True)
class ParsedShareToken:
    """Result of :func:`read_token`. Signature is **not** yet verified."""

    header: ShareTokenHeader
    embedded_ciphertext: bytes
    signature: bytes
    payload_bytes: bytes
    """Exact bytes the signature authenticates — pass this to
    :func:`guardiabox.core.rsa.RsaSign.verify`."""


def _build_payload(header: ShareTokenHeader, embedded_ciphertext: bytes) -> bytes:
    """Concatenate the header + DEK + footer + ciphertext into the signed payload."""
    head = _HEADER_PREFIX.pack(
        SHARE_TOKEN_MAGIC,
        SHARE_TOKEN_VERSION,
        header.sender_user_id.bytes,
        header.recipient_user_id.bytes,
        header.content_sha256,
        len(header.wrapped_dek),
    )
    foot = _FOOTER_FIELDS.pack(header.expires_at, header.permission_flags)
    return head + header.wrapped_dek + foot + embedded_ciphertext


def write_token(
    *,
    header: ShareTokenHeader,
    embedded_ciphertext: bytes,
    signature: bytes,
) -> bytes:
    """Serialise a ``.gbox-share`` token to its on-disk bytes.

    Args:
        header: The decoded header struct. Field invariants are enforced
            by :class:`ShareTokenHeader`'s ``__post_init__``.
        embedded_ciphertext: Raw ``.crypt`` bytes the recipient will
            decrypt with the unwrapped DEK.
        signature: The detached RSA-PSS signature over
            ``_build_payload(header, embedded_ciphertext)``. Must be
            exactly :data:`SIGNATURE_BYTES` long.

    Returns:
        ``payload || signature`` — the full on-disk file content.

    Raises:
        ValueError: If the signature length is wrong.
    """
    if len(signature) != SIGNATURE_BYTES:
        raise ValueError(f"signature must be {SIGNATURE_BYTES} bytes, got {len(signature)}")
    payload = _build_payload(header, embedded_ciphertext)
    return payload + signature


def build_payload_for_signing(
    header: ShareTokenHeader,
    embedded_ciphertext: bytes,
) -> bytes:
    """Return the bytes the sender must pass to :func:`RsaSign.sign`.

    This is :func:`_build_payload` exposed under a public name so the
    operations layer (:func:`share_file`) can compute the signature
    without rebuilding the payload twice.
    """
    return _build_payload(header, embedded_ciphertext)


def read_token(blob: bytes) -> ParsedShareToken:
    """Parse a ``.gbox-share`` blob without verifying the signature.

    The caller is responsible for handing ``parsed.payload_bytes`` and
    ``parsed.signature`` to :func:`guardiabox.core.rsa.RsaSign.verify`
    **before** consuming any field of ``parsed.header``. The accept-share
    flow enforces this ordering.

    Args:
        blob: Raw file bytes from disk.

    Returns:
        A :class:`ParsedShareToken`.

    Raises:
        InvalidContainerError: If the magic does not match.
        UnsupportedVersionError: If the version byte is not
            :data:`SHARE_TOKEN_VERSION`.
        CorruptedContainerError: If the layout is malformed (truncated
            file, claimed ``wrapped_dek_length`` exceeds the cap or
            overruns the buffer).
    """
    if len(blob) < _MIN_TOKEN_BYTES:
        raise CorruptedContainerError(
            f"share token too short: {len(blob)} bytes (minimum {_MIN_TOKEN_BYTES})"
        )

    payload_bytes = blob[:-SIGNATURE_BYTES]
    signature = blob[-SIGNATURE_BYTES:]

    magic, version, sender_b, recipient_b, content_sha256, dek_len = _HEADER_PREFIX.unpack_from(
        payload_bytes, 0
    )
    if magic != SHARE_TOKEN_MAGIC:
        raise InvalidContainerError(f"share token magic mismatch: {magic!r}")
    if version != SHARE_TOKEN_VERSION:
        raise UnsupportedVersionError(
            f"share token version {version} not supported "
            f"(this build expects {SHARE_TOKEN_VERSION})"
        )
    if dek_len > MAX_WRAPPED_DEK_BYTES:
        raise CorruptedContainerError(
            f"wrapped_dek_length {dek_len} exceeds maximum {MAX_WRAPPED_DEK_BYTES}"
        )

    cursor = _HEADER_PREFIX_SIZE
    if cursor + dek_len + _FOOTER_SIZE > len(payload_bytes):
        raise CorruptedContainerError("share token truncated within wrapped DEK or footer")
    wrapped_dek = payload_bytes[cursor : cursor + dek_len]
    cursor += dek_len
    expires_at, permission_flags = _FOOTER_FIELDS.unpack_from(payload_bytes, cursor)
    cursor += _FOOTER_SIZE

    embedded_ciphertext = payload_bytes[cursor:]

    header = ShareTokenHeader(
        sender_user_id=UUID(bytes=sender_b),
        recipient_user_id=UUID(bytes=recipient_b),
        content_sha256=content_sha256,
        wrapped_dek=wrapped_dek,
        expires_at=expires_at,
        permission_flags=permission_flags,
    )
    return ParsedShareToken(
        header=header,
        embedded_ciphertext=embedded_ciphertext,
        signature=signature,
        payload_bytes=payload_bytes,
    )
