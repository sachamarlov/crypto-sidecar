"""Guarantees on security-critical constants.

Any change to these values is a breaking container-format change. A failing
test here means ``CONTAINER_VERSION`` must be bumped and an ADR filed.
"""

from __future__ import annotations

from guardiabox.core import constants


def test_container_magic_is_ascii_gbox() -> None:
    assert constants.CONTAINER_MAGIC == b"GBOX"
    assert len(constants.CONTAINER_MAGIC) == 4


def test_container_version_is_one() -> None:
    assert constants.CONTAINER_VERSION == 1


def test_kdf_ids_are_distinct_and_byte_sized() -> None:
    assert constants.KDF_ID_PBKDF2_SHA256 != constants.KDF_ID_ARGON2ID
    assert 0 < constants.KDF_ID_PBKDF2_SHA256 <= 0xFF
    assert 0 < constants.KDF_ID_ARGON2ID <= 0xFF


def test_aes_key_and_nonce_match_aes_256_gcm() -> None:
    assert constants.AES_KEY_BYTES == 32
    assert constants.AES_GCM_NONCE_BYTES == 12
    assert constants.AES_GCM_TAG_BYTES == 16


def test_salt_at_least_128_bits() -> None:
    # NIST SP 800-132 §5.1 — salt ≥ 128 bits.
    assert constants.SALT_BYTES >= 16


def test_kdf_floors_match_owasp_2026() -> None:
    assert constants.PBKDF2_MIN_ITERATIONS >= 600_000
    assert constants.ARGON2_MIN_MEMORY_KIB >= 64 * 1024
    assert constants.ARGON2_MIN_TIME_COST >= 3
    assert constants.ARGON2_MIN_PARALLELISM >= 1


def test_chunk_size_at_least_4_kib() -> None:
    assert constants.DEFAULT_CHUNK_BYTES >= 4 * 1024


def test_file_suffixes_are_stable() -> None:
    assert constants.ENCRYPTED_SUFFIX == ".crypt"
    assert constants.DECRYPTED_SUFFIX == ".decrypt"
