"""Property-based tests on the streaming format, KDF-free.

``_encrypt_stream`` and ``_decrypt_stream_plaintext`` are the heart of the
chunked AEAD format. Running them with a fixed AES key (no KDF) lets
Hypothesis generate hundreds of cases per second — the 600 000-iteration
PBKDF2 derivation that dominates the ``encrypt_file`` / ``decrypt_file``
runtime never fires here.

Since Fix-1.P the cipher is key-bound: we build one
``AesGcmCipher(_KEY)`` per test and reuse it for every chunk.
"""

from __future__ import annotations

from io import BytesIO
import secrets

from hypothesis import HealthCheck, given, settings, strategies as st
import pytest

from guardiabox.core.constants import (
    AES_GCM_NONCE_BYTES,
    AES_KEY_BYTES,
    DEFAULT_CHUNK_BYTES,
)
from guardiabox.core.crypto import AesGcmCipher
from guardiabox.core.operations import (
    _decrypt_stream_plaintext,
    _encrypt_stream,
    _split_message,
)

_KEY = secrets.token_bytes(AES_KEY_BYTES)
_BASE_NONCE = secrets.token_bytes(AES_GCM_NONCE_BYTES)
_AAD_PREFIX = b"FAKE-HEADER-BYTES-FOR-TESTS"


@pytest.mark.property
@given(payload=st.binary(min_size=0, max_size=DEFAULT_CHUNK_BYTES * 3 + 17))
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.data_too_large])
def test_stream_roundtrip_any_bytes(payload: bytes) -> None:
    """Round-trip of an arbitrary byte-string through the chunk pipeline."""
    cipher = AesGcmCipher(_KEY)
    buf = BytesIO()
    _encrypt_stream(
        chunks=_split_message(payload, DEFAULT_CHUNK_BYTES),
        cipher=cipher,
        base_nonce=_BASE_NONCE,
        aad_prefix=_AAD_PREFIX,
        out=buf,
    )
    buf.seek(0)
    recovered = b"".join(
        _decrypt_stream_plaintext(
            raw_in=buf,
            cipher=cipher,
            base_nonce=_BASE_NONCE,
            aad_prefix=_AAD_PREFIX,
            chunk_bytes=DEFAULT_CHUNK_BYTES,
        )
    )
    assert recovered == payload


@pytest.mark.property
@given(
    payload=st.binary(min_size=1, max_size=DEFAULT_CHUNK_BYTES * 2),
    flip_index=st.integers(min_value=0),
)
@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.data_too_large])
def test_stream_bit_flip_anywhere_rejects(payload: bytes, flip_index: int) -> None:
    """Flipping any byte of the ciphertext invalidates the AEAD."""
    cipher = AesGcmCipher(_KEY)
    buf = BytesIO()
    _encrypt_stream(
        chunks=_split_message(payload, DEFAULT_CHUNK_BYTES),
        cipher=cipher,
        base_nonce=_BASE_NONCE,
        aad_prefix=_AAD_PREFIX,
        out=buf,
    )
    raw = bytearray(buf.getvalue())
    if not raw:
        return  # nothing to flip
    raw[flip_index % len(raw)] ^= 0x01

    tampered = BytesIO(bytes(raw))
    from guardiabox.core.exceptions import (
        CorruptedContainerError,
        DecryptionError,
    )

    with pytest.raises((DecryptionError, CorruptedContainerError)):
        list(
            _decrypt_stream_plaintext(
                raw_in=tampered,
                cipher=cipher,
                base_nonce=_BASE_NONCE,
                aad_prefix=_AAD_PREFIX,
                chunk_bytes=DEFAULT_CHUNK_BYTES,
            )
        )


@pytest.mark.parametrize(
    "payload_size",
    [
        DEFAULT_CHUNK_BYTES + 1,
        DEFAULT_CHUNK_BYTES * 2,
        DEFAULT_CHUNK_BYTES * 2 + 123,
        DEFAULT_CHUNK_BYTES * 4,
    ],
)
def test_stream_truncation_always_rejects(payload_size: int) -> None:
    """Dropping the last chunk must surface as an AEAD failure.

    Parametrised instead of Hypothesis-generated because a chunk-sized
    payload (≥ 64 KiB) saturates Hypothesis's default input budget. This is
    the central anti-truncation guarantee granted by the ``is_final`` bit
    in the chunk AAD (cf. ADR-0014).
    """
    payload = secrets.token_bytes(payload_size)
    cipher = AesGcmCipher(_KEY)
    buf = BytesIO()
    _encrypt_stream(
        chunks=_split_message(payload, DEFAULT_CHUNK_BYTES),
        cipher=cipher,
        base_nonce=_BASE_NONCE,
        aad_prefix=_AAD_PREFIX,
        out=buf,
    )
    raw = buf.getvalue()
    # Strip the last (ciphertext+tag) chunk entirely.
    assert len(raw) >= DEFAULT_CHUNK_BYTES
    full_chunk_ct = DEFAULT_CHUNK_BYTES + 16
    n_full_chunks = len(raw) // full_chunk_ct
    truncated = (
        raw[: (n_full_chunks - 1) * full_chunk_ct] if n_full_chunks > 1 else raw[:full_chunk_ct]
    )
    tampered = BytesIO(truncated)

    from guardiabox.core.exceptions import (
        CorruptedContainerError,
        DecryptionError,
    )

    with pytest.raises((DecryptionError, CorruptedContainerError)):
        list(
            _decrypt_stream_plaintext(
                raw_in=tampered,
                cipher=cipher,
                base_nonce=_BASE_NONCE,
                aad_prefix=_AAD_PREFIX,
                chunk_bytes=DEFAULT_CHUNK_BYTES,
            )
        )
