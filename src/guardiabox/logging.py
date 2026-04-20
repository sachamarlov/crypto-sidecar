"""Structured logging via :mod:`structlog`.

JSON output for production (machine-readable, ingestable by Loki/ELK), pretty
output for local development. Never log secrets — use the ``redact`` processor
to scrub well-known sensitive keys defensively.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, Processor

_REDACT_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passphrase",
        "master_password",
        "master_key",
        "vault_key",
        "private_key",
        "session_token",
        "api_key",
        "token",
        "secret",
        "salt",
    }
)


def _redact_secrets(_: Any, __: str, event_dict: EventDict) -> EventDict:
    """Scrub well-known sensitive keys before they hit any sink."""
    for key in list(event_dict.keys()):
        if key.lower() in _REDACT_KEYS:
            event_dict[key] = "<redacted>"
    return event_dict


def configure(level: str = "INFO", *, json: bool = False) -> None:
    """Configure structlog and the stdlib logger compatibility shim."""
    timestamper: Processor = structlog.processors.TimeStamper(fmt="iso", utc=True)

    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        _redact_secrets,
        timestamper,
    ]

    renderer: Processor = (
        structlog.processors.JSONRenderer() if json else structlog.dev.ConsoleRenderer(colors=True)
    )

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping()[level.upper()],
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger; ``name`` defaults to the caller module."""
    # structlog.get_logger() returns Any (BoundLoggerLazyProxy at module load),
    # but resolves to a real BoundLogger on first call. We assert the runtime
    # type for the type checker without paying for an isinstance check.
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger
