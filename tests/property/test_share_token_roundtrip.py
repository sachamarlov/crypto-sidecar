"""Property-based round-trip on :mod:`guardiabox.core.share_token`.

Asserts that ``read_token(write_token(...)) == original`` for arbitrary
header field combinations and embedded-ciphertext sizes.
"""

from __future__ import annotations

from uuid import UUID

from hypothesis import given, settings, strategies as st

from guardiabox.core.share_token import (
    MAX_WRAPPED_DEK_BYTES,
    SIGNATURE_BYTES,
    ShareTokenHeader,
    read_token,
    write_token,
)


@st.composite
def _header_strategy(draw: st.DrawFn) -> ShareTokenHeader:
    sender = UUID(bytes=draw(st.binary(min_size=16, max_size=16)))
    recipient = UUID(bytes=draw(st.binary(min_size=16, max_size=16)))
    content_sha256 = draw(st.binary(min_size=32, max_size=32))
    wrapped_dek = draw(st.binary(min_size=0, max_size=MAX_WRAPPED_DEK_BYTES))
    expires_at = draw(st.integers(min_value=0, max_value=2**64 - 1))
    permission_flags = draw(st.integers(min_value=0, max_value=2**32 - 1))
    return ShareTokenHeader(
        sender_user_id=sender,
        recipient_user_id=recipient,
        content_sha256=content_sha256,
        wrapped_dek=wrapped_dek,
        expires_at=expires_at,
        permission_flags=permission_flags,
    )


@settings(max_examples=100, deadline=None)
@given(
    header=_header_strategy(),
    embedded=st.binary(min_size=0, max_size=4096),
)
def test_write_read_roundtrip_property(
    header: ShareTokenHeader,
    embedded: bytes,
) -> None:
    sig = b"\x42" * SIGNATURE_BYTES
    blob = write_token(header=header, embedded_ciphertext=embedded, signature=sig)
    parsed = read_token(blob)

    assert parsed.header == header
    assert parsed.embedded_ciphertext == embedded
    assert parsed.signature == sig
    assert parsed.payload_bytes == blob[:-SIGNATURE_BYTES]
