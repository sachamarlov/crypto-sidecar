"""Performance benchmarks pinning ``docs/SPEC.md`` NFR-1 and NFR-2.

These are **soft** benchmarks: we assert loose lower bounds so CI variance
doesn't cause spurious failures, but a 10x regression would trigger the
guard. All tests are marked ``@pytest.mark.slow`` so the default suite stays
fast; run them with ``uv run pytest -m slow`` or ``uv run pytest
tests/perf``.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
import secrets
import time

import pytest

from guardiabox.core.constants import (
    AES_GCM_NONCE_BYTES,
    AES_KEY_BYTES,
    DEFAULT_CHUNK_BYTES,
)
from guardiabox.core.crypto import AesGcmCipher
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.core.operations import (
    _decrypt_stream_plaintext,
    _encrypt_stream,
    _split_message,
)

# Lower bound well below the NFR target to tolerate slow CI runners.
# NFR-1 asks for ≥ 100 MiB/s ; we assert ≥ 50 MiB/s to avoid flakes on GitHub
# Actions' shared VMs. Anything under 50 MiB/s is a real regression.
_MIN_THROUGHPUT_MIB_S = 50.0

# NFR-2 asks for 50 ms ≤ KDF ≤ 1 s. We assert a wider band because CI runners
# can be slower than a laptop while staying functionally correct.
# Lower bound (0.01 s) guards against a mis-pinned "zero iterations" regression.
_KDF_MIN_SECONDS = 0.01
# Upper bound (5 s) survives CI jitter without hiding a 10x regression.
_KDF_MAX_SECONDS = 5.0


@pytest.mark.slow
def test_aes_gcm_streaming_throughput(tmp_path: Path) -> None:
    """NFR-1 — AES-GCM streaming ≥ 100 MiB/s (asserted ≥ 50 MiB/s)."""
    key = secrets.token_bytes(AES_KEY_BYTES)
    cipher = AesGcmCipher(key)
    base_nonce = secrets.token_bytes(AES_GCM_NONCE_BYTES)
    aad = b"bench-header"

    payload_size_mib = 32
    payload = secrets.token_bytes(payload_size_mib * 1024 * 1024)

    # Encrypt
    buf = BytesIO()
    start = time.perf_counter()
    _encrypt_stream(
        chunks=_split_message(payload, DEFAULT_CHUNK_BYTES),
        cipher=cipher,
        base_nonce=base_nonce,
        aad_prefix=aad,
        out=buf,
    )
    elapsed_enc = time.perf_counter() - start
    enc_throughput = payload_size_mib / elapsed_enc

    # Decrypt
    buf.seek(0)
    start = time.perf_counter()
    recovered = b"".join(
        _decrypt_stream_plaintext(
            raw_in=buf,
            cipher=cipher,
            base_nonce=base_nonce,
            aad_prefix=aad,
            chunk_bytes=DEFAULT_CHUNK_BYTES,
        )
    )
    elapsed_dec = time.perf_counter() - start
    dec_throughput = payload_size_mib / elapsed_dec

    assert recovered == payload
    assert enc_throughput >= _MIN_THROUGHPUT_MIB_S, (
        f"Encrypt throughput {enc_throughput:.1f} MiB/s < floor {_MIN_THROUGHPUT_MIB_S} MiB/s"
    )
    assert dec_throughput >= _MIN_THROUGHPUT_MIB_S, (
        f"Decrypt throughput {dec_throughput:.1f} MiB/s < floor {_MIN_THROUGHPUT_MIB_S} MiB/s"
    )


@pytest.mark.slow
def test_pbkdf2_timing_within_nfr_2_band() -> None:
    """NFR-2 — PBKDF2 derivation within [0.01 s, 5 s] band on this host."""
    kdf = Pbkdf2Kdf()
    salt = secrets.token_bytes(16)

    start = time.perf_counter()
    kdf.derive(b"password", salt, 32)
    elapsed = time.perf_counter() - start

    assert _KDF_MIN_SECONDS <= elapsed <= _KDF_MAX_SECONDS, (
        f"PBKDF2 derivation took {elapsed:.3f} s, outside "
        f"[{_KDF_MIN_SECONDS}, {_KDF_MAX_SECONDS}] band"
    )


@pytest.mark.slow
def test_argon2id_timing_within_nfr_2_band() -> None:
    """NFR-2 — Argon2id derivation within [0.01 s, 5 s] band on this host."""
    kdf = Argon2idKdf()
    salt = secrets.token_bytes(16)

    start = time.perf_counter()
    kdf.derive(b"password", salt, 32)
    elapsed = time.perf_counter() - start

    assert _KDF_MIN_SECONDS <= elapsed <= _KDF_MAX_SECONDS, (
        f"Argon2id derivation took {elapsed:.3f} s, outside "
        f"[{_KDF_MIN_SECONDS}, {_KDF_MAX_SECONDS}] band"
    )
