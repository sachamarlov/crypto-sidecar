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

import sys
from typing import Final

from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
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


# Test mode: pytest registers itself in ``sys.modules`` before any
# of our packages are imported. When detected, disable the limiter
# so test suites that fire >60 encrypt/decrypt requests in a single
# process do not bump into the 60/minute production ceiling. A
# dedicated regression test re-enables the limiter via
# ``limiter.enabled = True`` to prove the gate still works.
_LIMITER_ENABLED = "pytest" not in sys.modules

limiter = Limiter(key_func=get_remote_address, enabled=_LIMITER_ENABLED)
"""Shared :class:`slowapi.Limiter` instance bound on app construction."""


def rate_limit_exceeded_handler(_: Request, __: Exception) -> JSONResponse:
    """Return a constant 429 body so callers cannot derive bucket details.

    The signature accepts :class:`Exception` rather than the narrower
    :class:`RateLimitExceeded` so it satisfies Starlette's
    ``add_exception_handler`` contract directly. The exception class
    is keyed by :class:`RateLimitExceeded` at registration time.
    """
    return JSONResponse(
        status_code=429,
        content={"detail": "rate limit exceeded"},
    )
