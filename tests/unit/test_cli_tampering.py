"""Tampering tests: flipping any header or payload byte must be rejected.

Exercises each structural region of the ``.crypt`` container — magic,
version byte, kdf_id, kdf_params, salt, base_nonce, ciphertext, final tag
— and asserts that the decrypt CLI exits with the **right** exit code
for that region's parse/auth failure.

Spec 002 `tasks.md` T-002.06:
> Tampering tests: bit-flip the magic / kdf_id / salt / base_nonce /
> a ciphertext byte / the final tag, expect InvalidContainerError or
> IntegrityError.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardiabox.ui.cli.io import ExitCode
from guardiabox.ui.cli.main import app

STRONG_PASSWORD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret


@pytest.fixture(name="runner")
def _runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(name="workdir")
def _workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture(name="sample_crypt")
def _sample_crypt(runner: CliRunner, workdir: Path) -> Path:
    """Encrypt a small file and return its .crypt container path."""
    source = workdir / "sample.bin"
    source.write_bytes(b"the magic words are squeamish ossifrage" * 8)
    enc = runner.invoke(
        app,
        ["encrypt", "sample.bin", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert enc.exit_code == ExitCode.OK, enc.stderr
    return workdir / "sample.bin.crypt"


def _flip_byte(path: Path, offset: int, mask: int = 0x01) -> None:
    raw = bytearray(path.read_bytes())
    raw[offset] ^= mask
    path.write_bytes(bytes(raw))


def _overwrite_range(path: Path, offset: int, data: bytes) -> None:
    raw = bytearray(path.read_bytes())
    raw[offset : offset + len(data)] = data
    path.write_bytes(bytes(raw))


def _decrypt(runner: CliRunner, crypt_name: str = "sample.bin.crypt") -> int:
    result = runner.invoke(
        app,
        ["decrypt", crypt_name, "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    return int(result.exit_code)


# Header layout (for PBKDF2): magic(4) + prefix(4) + params(4) + salt(16) + nonce(12)
# → total header = 40 bytes before ciphertext.


def test_tampering_magic_byte_rejected_as_data_error(
    runner: CliRunner, workdir: Path, sample_crypt: Path
) -> None:
    """Flipping a magic byte ⇒ InvalidContainerError ⇒ exit 65."""
    _flip_byte(sample_crypt, offset=0)
    assert _decrypt(runner) == ExitCode.DATA_ERROR


def test_tampering_version_byte_rejected_as_data_error(
    runner: CliRunner, workdir: Path, sample_crypt: Path
) -> None:
    """Flipping the version byte ⇒ UnsupportedVersionError ⇒ exit 65."""
    _flip_byte(sample_crypt, offset=4, mask=0x80)
    assert _decrypt(runner) == ExitCode.DATA_ERROR


def test_tampering_kdf_id_rejected_as_data_error(
    runner: CliRunner, workdir: Path, sample_crypt: Path
) -> None:
    """Overwriting kdf_id with 0xEE ⇒ UnknownKdfError ⇒ exit 65."""
    _overwrite_range(sample_crypt, offset=5, data=b"\xee")
    assert _decrypt(runner) == ExitCode.DATA_ERROR


def test_tampering_kdf_params_rejected_as_data_error_or_auth(
    runner: CliRunner, workdir: Path, sample_crypt: Path
) -> None:
    """Flipping the params region: either triggers the floor check (65) or a
    mis-derived key (2). Both are acceptable, neither is exit 0."""
    _flip_byte(sample_crypt, offset=8)  # first byte of PBKDF2 iterations uint32
    assert _decrypt(runner) in {ExitCode.DATA_ERROR, ExitCode.AUTH_FAILED}


def test_tampering_salt_byte_rejected_as_auth_failure(
    runner: CliRunner, workdir: Path, sample_crypt: Path
) -> None:
    """Salt lives at offset 12 (after 8-byte prefix + 4 PBKDF2 params).

    A single flipped bit changes the derived key → AES-GCM tag mismatch →
    exit 2 via the anti-oracle branch.
    """
    _flip_byte(sample_crypt, offset=12)
    assert _decrypt(runner) == ExitCode.AUTH_FAILED


def test_tampering_base_nonce_byte_rejected_as_auth_failure(
    runner: CliRunner, workdir: Path, sample_crypt: Path
) -> None:
    """Base nonce starts at offset 28 for PBKDF2 (12+16). Flip ⇒ exit 2."""
    _flip_byte(sample_crypt, offset=28)
    assert _decrypt(runner) == ExitCode.AUTH_FAILED


def test_tampering_ciphertext_byte_rejected_as_auth_failure(
    runner: CliRunner, workdir: Path, sample_crypt: Path
) -> None:
    """Flip the first byte of ciphertext (right after the 40-byte header)."""
    _flip_byte(sample_crypt, offset=40)
    assert _decrypt(runner) == ExitCode.AUTH_FAILED


def test_tampering_tag_byte_rejected_as_auth_failure(
    runner: CliRunner, workdir: Path, sample_crypt: Path
) -> None:
    """The AES-GCM tag sits in the last 16 bytes of the final chunk."""
    _flip_byte(sample_crypt, offset=-1)
    assert _decrypt(runner) == ExitCode.AUTH_FAILED


def test_none_of_the_tamperings_produce_a_decrypt_file(
    runner: CliRunner, workdir: Path, sample_crypt: Path
) -> None:
    """Exhaustive parametrisation: whichever region we touch, the command
    must never create a ``.decrypt`` file (anti-partial-output discipline)."""
    offsets = [0, 4, 5, 8, 12, 28, 40, -1]
    for offset in offsets:
        # Reset container before each mutation by re-encrypting.
        _flip_byte(sample_crypt, offset=offset)
        result = runner.invoke(
            app,
            ["decrypt", "sample.bin.crypt", "--password-stdin"],
            input=f"{STRONG_PASSWORD}\n",
        )
        assert result.exit_code != ExitCode.OK
        assert not (workdir / "sample.bin.decrypt").exists(), (
            f"Tampering at offset {offset} produced a leaking .decrypt file"
        )
        # Restore the byte so the next iteration operates on a recoverable
        # baseline (flipping twice = identity for XOR 0x01).
        _flip_byte(sample_crypt, offset=offset)
