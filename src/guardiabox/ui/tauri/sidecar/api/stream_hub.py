"""Per-session pub/sub hub for WebSocket progress events (G-10).

The hub maps a vault session id to a list of subscriber
:class:`asyncio.Queue` instances. Routers publish JSON-serialisable
frames; the WebSocket handler in :mod:`api.ws` drains its own queue
and forwards the frames to the renderer.

A single session can have multiple WebSocket subscribers (multi-
tab UX): every frame is fan-out to every subscriber's queue.

The hub is intentionally in-memory; on lifespan shutdown the
SessionStore reaps every session and we drop the queues then. No
durability requirement.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
import contextlib
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from guardiabox.logging import get_logger

__all__ = [
    "StreamFrame",
    "StreamHub",
]

_log = get_logger("guardiabox.sidecar.stream_hub")

#: Bound on how many unconsumed frames a queue holds before back-
#: pressure kicks in. A slow / dead WebSocket consumer cannot grow
#: memory unbounded; once the cap is hit we drop new frames for
#: that subscriber and log a warning.
_QUEUE_MAX = 256


@dataclass(slots=True)
class StreamFrame:
    """A typed JSON payload broadcast to a session's subscribers."""

    event: str  # "progress" | "done" | "error" | "started"
    operation_id: str
    payload: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "event": self.event,
            "operation_id": self.operation_id,
            **self.payload,
        }


class StreamHub:
    """In-memory pub/sub for per-session progress events.

    The router calls :meth:`publish` (synchronous from a sync
    handler, or directly from an async handler). The WebSocket
    handler in :mod:`api.ws` calls :meth:`subscribe` which yields
    a queue scoped to the session; on disconnect the queue is
    automatically removed via the async context manager.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue[StreamFrame]]] = {}

    def publish(self, session_id: str, frame: StreamFrame) -> int:
        """Fan-out ``frame`` to every subscriber of ``session_id``.

        Returns the number of subscribers reached. Returns 0 if no
        WS is currently listening; that is not an error -- routers
        publish opportunistically.
        """
        queues = self._subscribers.get(session_id, [])
        delivered = 0
        for q in queues:
            try:
                q.put_nowait(frame)
                delivered += 1
            except asyncio.QueueFull:
                _log.warning(
                    "stream.queue_full",
                    operation_id=frame.operation_id,
                    frame_event=frame.event,
                )
        return delivered

    @asynccontextmanager
    async def subscribe(self, session_id: str) -> AsyncIterator[asyncio.Queue[StreamFrame]]:
        """Async context manager that yields a fresh queue.

        On exit the queue is removed from the session bucket and any
        frames it still holds are dropped. The hub guarantees no
        leak across reconnects.
        """
        queue: asyncio.Queue[StreamFrame] = asyncio.Queue(maxsize=_QUEUE_MAX)
        self._subscribers.setdefault(session_id, []).append(queue)
        _log.info("stream.subscribed", subscribers=len(self._subscribers[session_id]))
        try:
            yield queue
        finally:
            with contextlib.suppress(ValueError, KeyError):
                self._subscribers[session_id].remove(queue)
                if not self._subscribers[session_id]:
                    del self._subscribers[session_id]
            _log.info("stream.unsubscribed")

    def subscriber_count(self, session_id: str) -> int:
        """Return the number of active subscribers for ``session_id``."""
        return len(self._subscribers.get(session_id, []))

    def session_count(self) -> int:
        """Return the number of sessions with at least one subscriber."""
        return len(self._subscribers)
