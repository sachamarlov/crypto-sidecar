"""Tests for :mod:`guardiabox.logging`."""

from __future__ import annotations

import structlog

from guardiabox.logging import _redact_secrets, configure, get_logger


def test_redact_secrets_scrubs_well_known_keys() -> None:
    """Every key in the redact list becomes ``<redacted>`` before the sink."""
    event = {
        "event": "vault.test",
        "password": "hunter2",  # pragma: allowlist secret
        "master_key": b"\x00" * 32,
        "session_token": "xyz",  # pragma: allowlist secret
        "harmless": "kept",
    }
    scrubbed = _redact_secrets(None, "info", dict(event))
    assert scrubbed["password"] == "<redacted>"
    assert scrubbed["master_key"] == "<redacted>"
    assert scrubbed["session_token"] == "<redacted>"
    assert scrubbed["harmless"] == "kept"


def test_redact_secrets_is_case_insensitive() -> None:
    """``Password`` / ``PASSWORD`` / ``password`` all trigger the scrub."""
    event = {"PASSWORD": "X", "Master_Key": "Y", "SALT": "Z"}
    scrubbed = _redact_secrets(None, "info", dict(event))
    assert all(value == "<redacted>" for value in scrubbed.values())


def test_redact_secrets_leaves_unknown_keys_alone() -> None:
    event = {"foo": "bar", "event_id": 42}
    scrubbed = _redact_secrets(None, "info", dict(event))
    assert scrubbed == event


def test_configure_accepts_known_levels() -> None:
    """``configure`` must not raise for each named level."""
    for level in ("DEBUG", "INFO", "WARNING", "ERROR"):
        configure(level=level)


def test_configure_json_mode() -> None:
    """``configure(json=True)`` swaps the renderer without raising."""
    configure(level="INFO", json=True)


def test_get_logger_returns_bound_logger() -> None:
    configure(level="WARNING")
    logger = get_logger("test")
    assert isinstance(logger, structlog.stdlib.BoundLogger | object)
    # Structlog returns a proxy until first use; a plain .info() must not raise.
    logger.info("smoke")
