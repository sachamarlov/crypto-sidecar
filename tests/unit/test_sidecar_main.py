"""Unit tests for the sidecar entry-point helpers (G-01)."""

from __future__ import annotations

from io import StringIO
import socket

import pytest

from guardiabox.ui.tauri.sidecar import main as main_module


def test_generate_session_token_yields_url_safe_string() -> None:
    """``secrets.token_urlsafe(32)`` returns at least 32 base64url characters."""
    token = main_module._generate_session_token()

    # ``token_urlsafe(32)`` produces ~43 characters; we floor at 32 to be
    # robust to future tightening of the backing call.
    assert len(token) >= 32
    # base64url alphabet only.
    assert all(c.isalnum() or c in "-_" for c in token)


def test_generate_session_token_is_unique() -> None:
    """Two consecutive draws must differ -- the OS CSPRNG owns the entropy."""
    a = main_module._generate_session_token()
    b = main_module._generate_session_token()

    assert a != b


def test_pick_free_port_returns_loopback_assignable_port() -> None:
    """The port the kernel hands back must accept a fresh bind on loopback."""
    port = main_module._pick_free_port("127.0.0.1")

    assert 1 <= port <= 65535
    # Round-trip: bind it again to confirm the OS released it.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", port))


def test_print_handshake_format(monkeypatch: pytest.MonkeyPatch) -> None:
    """The handshake line matches the Rust shell parser contract."""
    fake_stdout = StringIO()
    monkeypatch.setattr("sys.stdout", fake_stdout)

    main_module._print_handshake(port=51234, token="aBc-_token-43-chars")

    output = fake_stdout.getvalue()
    assert output == "GUARDIABOX_SIDECAR=51234 aBc-_token-43-chars\n"


def test_handshake_prefix_constant() -> None:
    """The Rust parser greps for this exact prefix; lock the contract."""
    assert main_module._HANDSHAKE_PREFIX == "GUARDIABOX_SIDECAR"


def test_token_bytes_floor() -> None:
    """ADR-0016: 32 bytes -> 256 bits of entropy minimum."""
    assert main_module._TOKEN_BYTES >= 32
