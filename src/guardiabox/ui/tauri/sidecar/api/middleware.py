"""Token authentication middleware for the sidecar (ADR-0016 §A).

Every inbound request is checked against the per-launch session
token stored at ``app.state.session_token``. The comparison goes
through :func:`hmac.compare_digest` so a timing attack on the token
itself is foreclosed (CWE-208).

Whitelisted paths:

* ``/healthz`` -- liveness, used by the Tauri shell pre-handshake.
* ``/readyz``  -- vault initialisation probe.
* ``/version`` -- build metadata.
* ``/openapi.json`` -- the codegen pipeline (Phase H) fetches the
  schema offline; the document carries no secret material so leaving
  it unauthenticated avoids a chicken-and-egg between the auth
  middleware and the auto-generated client.

On rejection the middleware returns a single, constant body
(``{"detail": "missing or invalid token"}``). The structlog event
``auth.rejected`` records the source IP and the path *but never the
attempted token* -- redaction is enforced both by the
``_redact_secrets`` processor and by simply not passing the token
into the event.
"""

from __future__ import annotations

import hmac

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from guardiabox.logging import get_logger

__all__ = [
    "AUTH_EXEMPT_PATHS",
    "TOKEN_HEADER",
    "TokenAuthMiddleware",
]

#: Header carrying the launch token. The Tauri shell injects it on
#: every fetch call. Frontend devs must not log this header.
#: This is a header name, not a secret -- the actual token lives in
#: ``app.state.session_token`` and is never embedded as a literal.
TOKEN_HEADER = "x-guardiabox-token"  # noqa: S105  # nosec B105 -- header name, not a credential

#: Endpoints that bypass authentication. Kept narrow on purpose --
#: every addition must be justified by an inability to authenticate
#: pre-handshake (the boot probe) or by a documented public artefact
#: (the OpenAPI schema).
AUTH_EXEMPT_PATHS: frozenset[str] = frozenset(
    {
        "/healthz",
        "/readyz",
        "/version",
        "/openapi.json",
    }
)

_AUTH_FAILURE_BODY: dict[str, str] = {"detail": "missing or invalid token"}

_log = get_logger("guardiabox.sidecar.middleware")


class TokenAuthMiddleware(BaseHTTPMiddleware):
    """Reject every request that does not carry the right token.

    The token lives on ``app.state.session_token`` (set by the
    factory in ``app.py``). The middleware reads it on each request
    rather than caching at construction time so a future hot-rotation
    feature would not require restarting the whole app.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        if request.url.path in AUTH_EXEMPT_PATHS:
            return await call_next(request)

        provided = request.headers.get(TOKEN_HEADER)
        expected: str = request.app.state.session_token

        if provided is None or not hmac.compare_digest(
            provided.encode("utf-8"), expected.encode("utf-8")
        ):
            _log.info(
                "auth.rejected",
                path=request.url.path,
                client=request.client.host if request.client else "unknown",
                # The token itself is NEVER logged, even via structlog
                # _redact_secrets -- we don't even pass it.
            )
            return JSONResponse(status_code=401, content=_AUTH_FAILURE_BODY)

        return await call_next(request)
