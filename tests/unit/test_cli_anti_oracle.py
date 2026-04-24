"""Anti-oracle tests for ``guardiabox decrypt``.

The spec 002 acceptance criterion is that **an attacker observing the CLI's
output cannot distinguish wrong-password from tampered-ciphertext**. The
failing command must emit the exact same stderr bytes and exit code in
both cases.

Two external auditors found in April 2026 that the original
``CliRunner``-based test was blind to the process's real ``sys.stderr``
(structlog's ``PrintLoggerFactory`` wrote there directly, Click's runner
captures only ``typer.echo(err=True)``). This file therefore drives the
CLI through :func:`subprocess.run`, which captures **both** the Typer
echo and any structlog emission. Any new log written to stderr is caught
— the test fails closed.
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys

import pytest

STRONG_PASSWORD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
WRONG_PASSWORD = "A_Different_Strong_Password_42!"  # pragma: allowlist secret

_EXIT_AUTH_FAILED = 2
_ANSI_RE = re.compile(rb"\x1b\[[0-9;]*m")


def _strip_ansi(b: bytes) -> bytes:
    """Drop terminal escape sequences so the comparison is shell-agnostic."""
    return _ANSI_RE.sub(b"", b)


def _run_decrypt(cwd: Path, crypt_name: str, password: str) -> subprocess.CompletedProcess[bytes]:
    """Run ``python -m guardiabox decrypt <crypt> --password-stdin``.

    Returns the full CompletedProcess so callers can inspect exit code,
    real stdout, and real stderr (including any leak from a background
    logger).
    """
    return subprocess.run(
        [sys.executable, "-m", "guardiabox", "decrypt", crypt_name, "--password-stdin"],
        cwd=str(cwd),
        input=(password + "\n").encode("utf-8"),
        capture_output=True,
        check=False,
        timeout=120,
    )


def _encrypt_sample(tmp_path: Path, plaintext: bytes = b"anti-oracle probe") -> Path:
    """Encrypt a small file via subprocess and return the .crypt path."""
    source = tmp_path / "sample.bin"
    source.write_bytes(plaintext)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "guardiabox",
            "encrypt",
            "sample.bin",
            "--password-stdin",
        ],
        cwd=str(tmp_path),
        input=(STRONG_PASSWORD + "\n").encode("utf-8"),
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"setup encrypt failed: rc={result.returncode} "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    return tmp_path / "sample.bin.crypt"


@pytest.mark.integration
def test_wrong_password_and_tampered_chunk_share_exact_real_stderr(
    tmp_path: Path,
) -> None:
    """Anti-oracle — run against **real** sys.stderr via subprocess.

    CliRunner captures only ``typer.echo(err=True)`` — a previous version
    of this test passed while structlog still leaked the exception class
    on the actual process stderr. This subprocess-based test intercepts
    every byte written to fd 2, including background loggers.
    """
    crypt = _encrypt_sample(tmp_path)

    # 1) Wrong password run.
    wrong = _run_decrypt(tmp_path, "sample.bin.crypt", WRONG_PASSWORD)

    # 2) Tampered ciphertext (flip the last byte — the AES-GCM tag).
    raw = bytearray(crypt.read_bytes())
    raw[-1] ^= 0x01
    crypt.write_bytes(bytes(raw))
    tampered = _run_decrypt(tmp_path, "sample.bin.crypt", STRONG_PASSWORD)

    # Identical exit code.
    assert wrong.returncode == _EXIT_AUTH_FAILED, wrong.stderr
    assert tampered.returncode == _EXIT_AUTH_FAILED, tampered.stderr

    # Identical stderr bytes after ANSI strip. No `reason=<ClassName>`,
    # no exception detail, no structlog event.
    assert _strip_ansi(wrong.stderr) == _strip_ansi(tampered.stderr), (
        f"Anti-oracle leak — stderr differs:\n"
        f"  wrong-password stderr: {wrong.stderr!r}\n"
        f"  tampered stderr:       {tampered.stderr!r}"
    )

    # And no exception class name ever appears on stderr.
    for forbidden in (b"DecryptionError", b"IntegrityError", b"CorruptedContainerError"):
        assert forbidden not in wrong.stderr, f"stderr leaks {forbidden!r}: {wrong.stderr!r}"
        assert forbidden not in tampered.stderr, f"stderr leaks {forbidden!r}: {tampered.stderr!r}"


@pytest.mark.integration
@pytest.mark.parametrize(
    ("tamper_offset", "description"),
    [
        (12, "salt byte"),
        (28, "base_nonce byte"),
        (40, "first ciphertext byte"),
        (-1, "final tag byte"),
    ],
)
def test_post_kdf_tamper_produces_same_stderr_as_wrong_password(
    tmp_path: Path, tamper_offset: int, description: str
) -> None:
    """Every post-KDF tamper point must be indistinguishable from wrong pwd."""
    crypt = _encrypt_sample(tmp_path)
    wrong = _run_decrypt(tmp_path, "sample.bin.crypt", WRONG_PASSWORD)

    raw = bytearray(crypt.read_bytes())
    raw[tamper_offset] ^= 0x01
    crypt.write_bytes(bytes(raw))
    tampered = _run_decrypt(tmp_path, "sample.bin.crypt", STRONG_PASSWORD)

    assert wrong.returncode == _EXIT_AUTH_FAILED
    assert tampered.returncode == _EXIT_AUTH_FAILED, (
        f"{description} at offset {tamper_offset}: exit {tampered.returncode}, "
        f"stderr={tampered.stderr!r}"
    )
    assert _strip_ansi(wrong.stderr) == _strip_ansi(tampered.stderr), description


@pytest.mark.integration
def test_truncated_ciphertext_stream_is_auth_failure_not_data_error(
    tmp_path: Path,
) -> None:
    """A truncated ciphertext chain must exit 2 (anti-oracle), not 65.

    Before Fix-1.A, ``_decrypt_stream_plaintext`` raised
    ``CorruptedContainerError`` on short reads, which the CLI mapped to
    exit 65 (DATA_ERROR) — an oracle an attacker could use to tell
    truncation from a wrong password. The post-KDF stream now raises
    :class:`DecryptionError`, routed to exit 2.
    """
    crypt = _encrypt_sample(tmp_path, plaintext=b"X" * 4096)
    raw = crypt.read_bytes()

    # Keep the 40-byte PBKDF2 header, then cut 20 bytes into the single
    # ciphertext chunk — smaller than the 16-byte GCM tag so the decoder
    # fails on short read.
    crypt.write_bytes(raw[: 40 + 20])
    result = _run_decrypt(tmp_path, "sample.bin.crypt", STRONG_PASSWORD)

    assert result.returncode == _EXIT_AUTH_FAILED, (
        f"truncation must exit 2, not {result.returncode}: {result.stderr!r}"
    )


@pytest.mark.integration
def test_wrong_password_does_not_create_decrypt_file(tmp_path: Path) -> None:
    """No .decrypt file must linger after a failed decryption."""
    _encrypt_sample(tmp_path)
    result = _run_decrypt(tmp_path, "sample.bin.crypt", WRONG_PASSWORD)
    assert result.returncode == _EXIT_AUTH_FAILED
    assert not (tmp_path / "sample.bin.decrypt").exists()
