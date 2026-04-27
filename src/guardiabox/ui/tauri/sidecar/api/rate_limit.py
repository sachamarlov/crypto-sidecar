"""slowapi-based rate limiter for the sidecar (G-11, ADR-0016 sec D).

Buckets per endpoint group:

* ``/vault/unlock`` and ``/users/{id}/unlock`` -- 5/min. The
  load-bearing brute-force ceiling: at PBKDF2 600 000 iterations,
  5 attempts/min over a zxcvbn-3 password (~35 bits) gives an
  expected crack window of >10 000 years.
* ``/encrypt``, ``/decrypt``, ``/share``, ``/accept``,
  ``/secure-delete`` -- 60/min.
* ``/users`` (CRUD), ``/init`` -- 30/min.
* Read-only endpoints -- 600/min.

Configuration is centralised so the THREAT_MODEL update (G-20) can
cite a single set of values.

The router decorators apply ``@limiter.limit(...)`` lazily; the
shared :class:`Limiter` instance is created here and exported for
the app factory to bind onto ``app.state.limiter`` + an exception
handler for :class:`slowapi.errors.RateLimitExceeded`.
"""

from __future__ import annotations

from typing import Final

from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

__all__ = [
    "BUCKET_AUTH_UNLOCK",
    "BUCKET_CRUD",
    "BUCKET_READ_ONLY",
    "BUCKET_WRITE",
    "limiter",
    "rate_limit_exceeded_handler",
]

#: Brute-force gate: 5 attempts per minute per source IP.
BUCKET_AUTH_UNLOCK: Final[str] = "5/minute"

#: Mutating writes (encrypt / decrypt / share / accept / secure-delete).
BUCKET_WRITE: Final[str] = "60/minute"

#: User and vault CRUD: bounded but not as tight as auth.
BUCKET_CRUD: Final[str] = "30/minute"

#: Read-only diagnostic endpoints.
BUCKET_READ_ONLY: Final[str] = "600/minute"


limiter = Limiter(key_func=get_remote_address)
"""Shared :class:`slowapi.Limiter` instance bound on app construction."""


def rate_limit_exceeded_handler(_: Request, __: RateLimitExceeded) -> JSONResponse:
    """Return a constant 429 body so callers cannot derive bucket details."""
    return JSONResponse(
        status_code=429,
        content={"detail": "rate limit exceeded"},
    )
