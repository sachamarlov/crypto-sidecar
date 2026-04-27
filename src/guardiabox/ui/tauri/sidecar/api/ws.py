"""WebSocket /api/v1/stream -- progress event subscription (G-10).

Auth: launch token + active session, both passed as query string
parameters because browser WebSocket clients cannot send custom
headers (the Tauri shell forwards them through the loopback URL).

Frame format (JSON):

* ``{"event": "started", "operation_id": "...", ...}``
* ``{"event": "progress", "operation_id": "...", "percent": int, ...}``
* ``{"event": "done", "operation_id": "...", "result": {...}}``
* ``{"event": "error", "operation_id": "...", "detail": "..."}``

Anti-oracle (ADR-0016 sec C): the ``error`` event for decrypt /
accept failures carries the *constant* detail string only, never
the underlying exception class. Routers that publish such errors
must use the unified anti-oracle string.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
from typing import Annotated

from fastapi import APIRouter, Query, WebSocket, status

from guardiabox.logging import get_logger
from guardiabox.ui.tauri.sidecar.api.stream_hub import StreamHub
from guardiabox.ui.tauri.sidecar.state import SessionStore

__all__ = ["build_ws_router"]

_log = get_logger("guardiabox.sidecar.ws")


def build_ws_router() -> APIRouter:
    """Return the ``/api/v1/stream`` WebSocket router."""
    router = APIRouter(prefix="/api/v1", tags=["stream"])

    @router.websocket("/stream")
    async def stream_endpoint(
        websocket: WebSocket,
        token: Annotated[str, Query()] = "",
        session: Annotated[str, Query()] = "",
    ) -> None:
        # ---- Authenticate ------------------------------------------------
        # Browser WS clients cannot send custom headers, so the launch
        # token + session id ride in the query string. We still use
        # constant-time comparison on the launch token (CWE-208).
        expected_token: str = websocket.app.state.session_token
        if not token or not hmac.compare_digest(
            token.encode("utf-8"), expected_token.encode("utf-8")
        ):
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="missing or invalid token",
            )
            return

        store: SessionStore = websocket.app.state.session_store
        vault_session = store.get(session) if session else None
        if vault_session is None:
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="vault session required",
            )
            return

        await websocket.accept()
        _log.info("stream.accepted", session=session[:8] + "...")

        hub: StreamHub = websocket.app.state.stream_hub
        try:
            async with hub.subscribe(session) as queue:
                while True:
                    # asyncio.wait_for lets us surface client
                    # disconnects (the recv() coro raises) without
                    # blocking the queue forever.
                    recv_task = asyncio.create_task(websocket.receive_text())
                    queue_task = asyncio.create_task(queue.get())
                    done, pending = await asyncio.wait(
                        [recv_task, queue_task],
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for task in pending:
                        task.cancel()
                        with contextlib.suppress(asyncio.CancelledError, Exception):
                            await task

                    if recv_task in done:
                        # Client closed the connection or sent text we
                        # don't process (the protocol is server -> client
                        # only). Either way we exit the loop.
                        with contextlib.suppress(Exception):
                            recv_task.result()
                        break

                    frame = queue_task.result()
                    await websocket.send_json(frame.to_json())
        except Exception as exc:
            _log.warning("stream.handler_error", error=str(exc))
        finally:
            with contextlib.suppress(Exception):
                await websocket.close()

    return router
