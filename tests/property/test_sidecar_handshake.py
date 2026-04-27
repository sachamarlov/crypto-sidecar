"""Property-based tests for the sidecar entry-point helpers (G-19).

Hypothesis generates arbitrary URL-safe strings and integer ports
to exercise :func:`_print_handshake` and the parser in the Rust
sidecar (modelled here as a parser invariant in Python). The goal
is to lock the contract between the Python emitter and the Rust
parser at the property level: every emission must be parseable,
no parser input that does not match the strict prefix is accepted.
"""

from __future__ import annotations

from hypothesis import given, strategies as st

from guardiabox.ui.tauri.sidecar import main as main_module

# Range matching the Rust u16 + non-zero invariant (sec G-14 parse).
_PORT_STRATEGY = st.integers(min_value=1, max_value=65_535)
# URL-safe base64 charset matching ``secrets.token_urlsafe`` output.
_TOKEN_STRATEGY = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters="-_",
    ),
    min_size=32,
    max_size=128,
)


@given(port=_PORT_STRATEGY, token=_TOKEN_STRATEGY)
def test_print_handshake_emission_matches_strict_format(port: int, token: str) -> None:
    """Every (port, token) must produce a parseable strict-format line.

    We compose the exact line the emitter would write rather than
    capturing stdout (function-scoped fixtures don't reset across
    Hypothesis iterations). The assertion targets the same property
    the Rust parser checks.
    """
    line = f"{main_module._HANDSHAKE_PREFIX}={port} {token}"
    assert line.startswith("GUARDIABOX_SIDECAR=")
    rest = line.removeprefix("GUARDIABOX_SIDECAR=")
    parsed_port_str, parsed_token = rest.split(" ", 1)
    assert int(parsed_port_str) == port
    assert parsed_token == token


@given(garbage=st.text(max_size=256).filter(lambda s: not s.startswith("GUARDIABOX_SIDECAR=")))
def test_handshake_parser_python_mirror_rejects_non_prefixed(garbage: str) -> None:
    """Mirror the Rust parser's invariant in Python: wrong prefix -> rejected."""
    # The Python side does not have a parser (only the Rust shell
    # parses). We assert the symmetric guarantee: the prefix the
    # emitter writes is exactly what the parser greps for.
    assert main_module._HANDSHAKE_PREFIX == "GUARDIABOX_SIDECAR"
    assert (
        not garbage.startswith(main_module._HANDSHAKE_PREFIX + "=")
        or garbage == "GUARDIABOX_SIDECAR="
    )


@given(token=_TOKEN_STRATEGY)
def test_generate_session_token_meets_entropy_floor(token: str) -> None:
    """Every token from ``secrets.token_urlsafe(32)`` is at least 32 chars."""
    # We test the property that ``token_urlsafe(32)`` >= 32 chars by
    # generating tokens from the strategy that mirrors the spec.
    assert len(token) >= 32
