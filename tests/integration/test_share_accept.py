"""Integration tests for ``share_file`` / ``accept_share`` (T-003.04+05).

The 4096-bit fixtures are session-scoped so the ~1 s key generation cost
is amortised across the whole module. Each test takes a generous arg
list of fixtures — pylint's PLR0917 fires on these signatures, but the
rule does not apply to pytest-injected dependencies (they arrive by
keyword binding, not positional). We silence per-function with the noqa
comment that documents this exception.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from guardiabox.core.exceptions import (
    DestinationAlreadyExistsError,
    DestinationCollidesWithSourceError,
    IntegrityError,
    ShareExpiredError,
)
from guardiabox.core.operations import (
    accept_share,
    encrypt_file,
    share_file,
)
from guardiabox.core.share_token import (
    PERMISSION_READ,
    PERMISSION_RESHARE,
    SIGNATURE_BYTES,
)

ALICE_PASSWORD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret


# ---------------------------------------------------------------------------
# Session-scoped RSA keypairs (slow to generate -- ~1 s for 4096-bit)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def alice_id() -> UUID:
    return UUID("11111111-1111-1111-1111-111111111111")


@pytest.fixture(scope="session")
def bob_id() -> UUID:
    return UUID("22222222-2222-2222-2222-222222222222")


@pytest.fixture(scope="session")
def charlie_id() -> UUID:
    return UUID("33333333-3333-3333-3333-333333333333")


@pytest.fixture
def encrypted_source(tmp_path: Path) -> Path:
    """Alice encrypts a small file under her password — returns the .crypt."""
    plaintext_path = tmp_path / "report.txt"
    plaintext_path.write_bytes(b"This is Alice's confidential payload.")
    return encrypt_file(plaintext_path, ALICE_PASSWORD, root=tmp_path)


# Production wraps SIGNATURE_BYTES = 512 (4096-bit). The test fixtures use
# 2048-bit (256-byte signature) for speed. We pad the signature with zeros
# in build_payload_for_signing? No — share_file uses the actual private key,
# whose signature length follows the modulus. We need to use 4096-bit keys
# to match the on-disk format expectation.
#
# Trade-off: 1 second per fixture is tolerable since we session-scope it.


@pytest.fixture(scope="session")
def alice_rsa_4096() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


@pytest.fixture(scope="session")
def bob_rsa_4096() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


@pytest.fixture(scope="session")
def charlie_rsa_4096() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


# ---------------------------------------------------------------------------
# Round-trip Alice -> Bob
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_share_then_accept_roundtrip(
    encrypted_source: Path,
    alice_rsa_4096: rsa.RSAPrivateKey,
    bob_rsa_4096: rsa.RSAPrivateKey,
    alice_id: UUID,
    bob_id: UUID,
    tmp_path: Path,
) -> None:
    share_path = tmp_path / "alice-to-bob.gbox-share"
    plaintext_out = tmp_path / "bob-decoded.txt"

    share_file(
        source=encrypted_source,
        sender_password=ALICE_PASSWORD,
        sender_user_id=alice_id,
        sender_private_key=alice_rsa_4096,
        recipient_user_id=bob_id,
        recipient_public_key=bob_rsa_4096.public_key(),
        output=share_path,
    )

    # On-disk file ends with the 512-byte RSA-PSS signature.
    assert share_path.exists()
    assert share_path.stat().st_size > SIGNATURE_BYTES

    accept_share(
        source=share_path,
        recipient_private_key=bob_rsa_4096,
        sender_public_key=alice_rsa_4096.public_key(),
        expected_recipient_user_id=bob_id,
        output=plaintext_out,
    )

    assert plaintext_out.read_bytes() == b"This is Alice's confidential payload."


# ---------------------------------------------------------------------------
# Tampering -> IntegrityError
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_tampered_signature_byte_raises_integrity_error(
    encrypted_source: Path,
    alice_rsa_4096: rsa.RSAPrivateKey,
    bob_rsa_4096: rsa.RSAPrivateKey,
    alice_id: UUID,
    bob_id: UUID,
    tmp_path: Path,
) -> None:
    share_path = tmp_path / "tampered.gbox-share"
    share_file(
        source=encrypted_source,
        sender_password=ALICE_PASSWORD,
        sender_user_id=alice_id,
        sender_private_key=alice_rsa_4096,
        recipient_user_id=bob_id,
        recipient_public_key=bob_rsa_4096.public_key(),
        output=share_path,
    )

    blob = bytearray(share_path.read_bytes())
    # Flip a byte deep in the RSA-PSS signature (last 512 bytes).
    blob[-100] ^= 0x01
    share_path.write_bytes(blob)

    with pytest.raises(IntegrityError):
        accept_share(
            source=share_path,
            recipient_private_key=bob_rsa_4096,
            sender_public_key=alice_rsa_4096.public_key(),
            expected_recipient_user_id=bob_id,
            output=tmp_path / "should-not-exist.bin",
        )
    assert not (tmp_path / "should-not-exist.bin").exists()


@pytest.mark.slow
def test_tampered_payload_byte_raises_integrity_error(
    encrypted_source: Path,
    alice_rsa_4096: rsa.RSAPrivateKey,
    bob_rsa_4096: rsa.RSAPrivateKey,
    alice_id: UUID,
    bob_id: UUID,
    tmp_path: Path,
) -> None:
    share_path = tmp_path / "tampered-payload.gbox-share"
    share_file(
        source=encrypted_source,
        sender_password=ALICE_PASSWORD,
        sender_user_id=alice_id,
        sender_private_key=alice_rsa_4096,
        recipient_user_id=bob_id,
        recipient_public_key=bob_rsa_4096.public_key(),
        output=share_path,
    )

    blob = bytearray(share_path.read_bytes())
    # Flip a byte inside the embedded ciphertext (well into payload, not signature).
    blob[200] ^= 0x01
    share_path.write_bytes(blob)

    with pytest.raises(IntegrityError):
        accept_share(
            source=share_path,
            recipient_private_key=bob_rsa_4096,
            sender_public_key=alice_rsa_4096.public_key(),
            expected_recipient_user_id=bob_id,
            output=tmp_path / "out.bin",
        )


@pytest.mark.slow
def test_wrong_sender_pubkey_raises_integrity_error(
    encrypted_source: Path,
    alice_rsa_4096: rsa.RSAPrivateKey,
    bob_rsa_4096: rsa.RSAPrivateKey,
    charlie_rsa_4096: rsa.RSAPrivateKey,
    alice_id: UUID,
    bob_id: UUID,
    tmp_path: Path,
) -> None:
    """Bob receives a token signed by Alice but tries to verify with Charlie's pubkey."""
    share_path = tmp_path / "alice-share.gbox-share"
    share_file(
        source=encrypted_source,
        sender_password=ALICE_PASSWORD,
        sender_user_id=alice_id,
        sender_private_key=alice_rsa_4096,
        recipient_user_id=bob_id,
        recipient_public_key=bob_rsa_4096.public_key(),
        output=share_path,
    )

    with pytest.raises(IntegrityError):
        accept_share(
            source=share_path,
            recipient_private_key=bob_rsa_4096,
            sender_public_key=charlie_rsa_4096.public_key(),  # WRONG
            expected_recipient_user_id=bob_id,
            output=tmp_path / "out.bin",
        )


@pytest.mark.slow
def test_recipient_mismatch_raises_integrity_error(
    encrypted_source: Path,
    alice_rsa_4096: rsa.RSAPrivateKey,
    bob_rsa_4096: rsa.RSAPrivateKey,
    charlie_rsa_4096: rsa.RSAPrivateKey,
    alice_id: UUID,
    bob_id: UUID,
    charlie_id: UUID,
    tmp_path: Path,
) -> None:
    """Token addressed to Charlie; Bob tries to accept (signature still valid)."""
    share_path = tmp_path / "alice-to-charlie.gbox-share"
    share_file(
        source=encrypted_source,
        sender_password=ALICE_PASSWORD,
        sender_user_id=alice_id,
        sender_private_key=alice_rsa_4096,
        recipient_user_id=charlie_id,
        recipient_public_key=charlie_rsa_4096.public_key(),
        output=share_path,
    )

    # Bob's keystore key matches no wrap inside the token. We assert
    # IntegrityError is raised at the recipient_user_id check (BEFORE
    # the unwrap fails) because that gives a clean, deterministic error.
    with pytest.raises(IntegrityError, match="different recipient"):
        accept_share(
            source=share_path,
            recipient_private_key=bob_rsa_4096,
            sender_public_key=alice_rsa_4096.public_key(),
            expected_recipient_user_id=bob_id,  # Bob, not Charlie
            output=tmp_path / "out.bin",
        )


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_expired_token_raises_share_expired_error(
    encrypted_source: Path,
    alice_rsa_4096: rsa.RSAPrivateKey,
    bob_rsa_4096: rsa.RSAPrivateKey,
    alice_id: UUID,
    bob_id: UUID,
    tmp_path: Path,
) -> None:
    """Past expires_at + a clock that is later -> ShareExpiredError."""
    share_path = tmp_path / "expired.gbox-share"
    past_epoch = 1_700_000_000  # 2023-11-14
    share_file(
        source=encrypted_source,
        sender_password=ALICE_PASSWORD,
        sender_user_id=alice_id,
        sender_private_key=alice_rsa_4096,
        recipient_user_id=bob_id,
        recipient_public_key=bob_rsa_4096.public_key(),
        output=share_path,
        expires_at=past_epoch,
    )

    with pytest.raises(ShareExpiredError):
        accept_share(
            source=share_path,
            recipient_private_key=bob_rsa_4096,
            sender_public_key=alice_rsa_4096.public_key(),
            expected_recipient_user_id=bob_id,
            output=tmp_path / "out.bin",
            now_epoch=past_epoch + 1,  # one second past expiry
        )


@pytest.mark.slow
def test_zero_expires_at_never_expires(
    encrypted_source: Path,
    alice_rsa_4096: rsa.RSAPrivateKey,
    bob_rsa_4096: rsa.RSAPrivateKey,
    alice_id: UUID,
    bob_id: UUID,
    tmp_path: Path,
) -> None:
    """expires_at = 0 means never -- accept must succeed regardless of clock."""
    share_path = tmp_path / "never-expires.gbox-share"
    share_file(
        source=encrypted_source,
        sender_password=ALICE_PASSWORD,
        sender_user_id=alice_id,
        sender_private_key=alice_rsa_4096,
        recipient_user_id=bob_id,
        recipient_public_key=bob_rsa_4096.public_key(),
        output=share_path,
        expires_at=0,
    )
    out = tmp_path / "out.bin"
    accept_share(
        source=share_path,
        recipient_private_key=bob_rsa_4096,
        sender_public_key=alice_rsa_4096.public_key(),
        expected_recipient_user_id=bob_id,
        output=out,
        now_epoch=2_000_000_000,  # arbitrary "future" clock
    )
    assert out.read_bytes() == b"This is Alice's confidential payload."


# ---------------------------------------------------------------------------
# Permission flags
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_permission_flags_resharing_bit_propagated(
    encrypted_source: Path,
    alice_rsa_4096: rsa.RSAPrivateKey,
    bob_rsa_4096: rsa.RSAPrivateKey,
    alice_id: UUID,
    bob_id: UUID,
    tmp_path: Path,
) -> None:
    share_path = tmp_path / "reshare-allowed.gbox-share"
    share_file(
        source=encrypted_source,
        sender_password=ALICE_PASSWORD,
        sender_user_id=alice_id,
        sender_private_key=alice_rsa_4096,
        recipient_user_id=bob_id,
        recipient_public_key=bob_rsa_4096.public_key(),
        output=share_path,
        permission_flags=PERMISSION_READ | PERMISSION_RESHARE,
    )

    # Bob accepts, then we re-read the token to inspect flags.
    from guardiabox.core.share_token import read_token  # local import for isolation

    parsed = read_token(share_path.read_bytes())
    assert parsed.header.permission_flags & PERMISSION_RESHARE


# ---------------------------------------------------------------------------
# Output path safety
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_share_refuses_destination_collides_with_source(
    encrypted_source: Path,
    alice_rsa_4096: rsa.RSAPrivateKey,
    bob_rsa_4096: rsa.RSAPrivateKey,
    alice_id: UUID,
    bob_id: UUID,
) -> None:
    with pytest.raises(DestinationCollidesWithSourceError):
        share_file(
            source=encrypted_source,
            sender_password=ALICE_PASSWORD,
            sender_user_id=alice_id,
            sender_private_key=alice_rsa_4096,
            recipient_user_id=bob_id,
            recipient_public_key=bob_rsa_4096.public_key(),
            output=encrypted_source,  # SAME PATH
        )


@pytest.mark.slow
def test_accept_refuses_existing_destination_without_force(
    encrypted_source: Path,
    alice_rsa_4096: rsa.RSAPrivateKey,
    bob_rsa_4096: rsa.RSAPrivateKey,
    alice_id: UUID,
    bob_id: UUID,
    tmp_path: Path,
) -> None:
    share_path = tmp_path / "alice.gbox-share"
    share_file(
        source=encrypted_source,
        sender_password=ALICE_PASSWORD,
        sender_user_id=alice_id,
        sender_private_key=alice_rsa_4096,
        recipient_user_id=bob_id,
        recipient_public_key=bob_rsa_4096.public_key(),
        output=share_path,
    )

    pre_existing = tmp_path / "out.bin"
    pre_existing.write_bytes(b"already here")

    with pytest.raises(DestinationAlreadyExistsError):
        accept_share(
            source=share_path,
            recipient_private_key=bob_rsa_4096,
            sender_public_key=alice_rsa_4096.public_key(),
            expected_recipient_user_id=bob_id,
            output=pre_existing,
        )
    assert pre_existing.read_bytes() == b"already here"


# ---------------------------------------------------------------------------
# Anti-oracle: signature failure must not leak whether expiry would have
# triggered. We assert by failing on signature first regardless of clock.
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_anti_oracle_signature_fails_before_expiry_check(
    encrypted_source: Path,
    alice_rsa_4096: rsa.RSAPrivateKey,
    bob_rsa_4096: rsa.RSAPrivateKey,
    charlie_rsa_4096: rsa.RSAPrivateKey,
    alice_id: UUID,
    bob_id: UUID,
    tmp_path: Path,
) -> None:
    """Tamper signature on a token that would otherwise be expired -- the
    user must see IntegrityError, NOT ShareExpiredError. If expiry leaked
    through tamper, an attacker could probe the token for liveness."""
    share_path = tmp_path / "tampered-and-expired.gbox-share"
    share_file(
        source=encrypted_source,
        sender_password=ALICE_PASSWORD,
        sender_user_id=alice_id,
        sender_private_key=alice_rsa_4096,
        recipient_user_id=bob_id,
        recipient_public_key=bob_rsa_4096.public_key(),
        output=share_path,
        expires_at=1_700_000_000,  # in the past
    )
    blob = bytearray(share_path.read_bytes())
    blob[-50] ^= 0x01  # corrupt signature
    share_path.write_bytes(blob)

    with pytest.raises(IntegrityError):
        accept_share(
            source=share_path,
            recipient_private_key=bob_rsa_4096,
            sender_public_key=alice_rsa_4096.public_key(),
            expected_recipient_user_id=bob_id,
            output=tmp_path / "out.bin",
            now_epoch=2_000_000_000,  # past expiry
        )
