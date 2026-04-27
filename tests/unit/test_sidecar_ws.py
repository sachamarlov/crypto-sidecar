"""Unit tests for /api/v1/stream WebSocket + StreamHub (G-10)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
import pytest_asyncio
from starlette.websockets import WebSocketDisconnect

from guardiabox.config import Settings
from guardiabox.persistence.bootstrap import init_vault
from guardiabox.ui.tauri.sidecar.api.middleware import TOKEN_HEADER
from guardiabox.ui.tauri.sidecar.api.stream_hub import StreamFrame, StreamHub
from guardiabox.ui.tauri.sidecar.app import create_app

_ADMIN_PWD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
_TEST_TOKEN = "test-token-32bytes-urlsafe-aaaa"  # pragma: allowlist secret


# ---------------------------------------------------------------------------
# Hub-only tests (no HTTP/WS roundtrip)
# ---------------------------------------------------------------------------


def test_hub_publish_to_no_subscribers_returns_zero() -> None:
    hub = StreamHub()
    delivered = hub.publish("ghost-session", StreamFrame("done", "op-1", {"ok": True}))
    assert delivered == 0


@pytest.mark.asyncio
async def test_hub_subscribe_yields_queue_then_cleans_up() -> None:
    hub = StreamHub()
    async with hub.subscribe("session-a") as queue:
        assert hub.subscriber_count("session-a") == 1
        hub.publish("session-a", StreamFrame("started", "op-1"))
        frame = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert frame.event == "started"
        assert frame.operation_id == "op-1"
    assert hub.subscriber_count("session-a") == 0


@pytest.mark.asyncio
async def test_hub_fanout_to_multiple_subscribers() -> None:
    hub = StreamHub()
    async with hub.subscribe("s") as q1, hub.subscribe("s") as q2:
        delivered = hub.publish("s", StreamFrame("done", "op-1", {"ok": True}))
        assert delivered == 2
        f1 = await asyncio.wait_for(q1.get(), timeout=1.0)
        f2 = await asyncio.wait_for(q2.get(), timeout=1.0)
        assert f1.event == "done"
        assert f2.event == "done"


@pytest.mark.asyncio
async def test_hub_isolated_per_session() -> None:
    hub = StreamHub()
    async with hub.subscribe("s-alice") as alice, hub.subscribe("s-bob") as bob:
        hub.publish("s-alice", StreamFrame("started", "op-a"))
        hub.publish("s-bob", StreamFrame("started", "op-b"))

        fa = await asyncio.wait_for(alice.get(), timeout=1.0)
        fb = await asyncio.wait_for(bob.get(), timeout=1.0)
        assert fa.operation_id == "op-a"
        assert fb.operation_id == "op-b"
        # Cross-contamination would have left a frame on the other queue.
        assert alice.empty()
        assert bob.empty()


def test_stream_frame_to_json_includes_payload() -> None:
    frame = StreamFrame("progress", "op-7", {"percent": 42, "bytes": 1024})
    assert frame.to_json() == {
        "event": "progress",
        "operation_id": "op-7",
        "percent": 42,
        "bytes": 1024,
    }


# ---------------------------------------------------------------------------
# WebSocket endpoint integration (TestClient)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def initialized_settings(tmp_path: Path) -> Settings:
    settings = Settings(data_dir=tmp_path)
    await init_vault(tmp_path, _ADMIN_PWD)
    return settings


@pytest.fixture
def authed_client_and_session(
    initialized_settings: Settings,
) -> tuple[TestClient, str]:
    app = create_app(session_token=_TEST_TOKEN, settings=initialized_settings)
    client = TestClient(app, headers={TOKEN_HEADER: _TEST_TOKEN})
    unlock = client.post("/api/v1/vault/unlock", json={"admin_password": _ADMIN_PWD})
    return client, unlock.json()["session_id"]


def test_ws_rejects_missing_token(initialized_settings: Settings) -> None:
    app = create_app(session_token=_TEST_TOKEN, settings=initialized_settings)
    client = TestClient(app)
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect("/api/v1/stream"),
    ):
        pass


def test_ws_rejects_wrong_token(initialized_settings: Settings) -> None:
    app = create_app(session_token=_TEST_TOKEN, settings=initialized_settings)
    client = TestClient(app)
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect("/api/v1/stream?token=wrong&session=abc"),
    ):
        pass


def test_ws_rejects_unknown_session(initialized_settings: Settings) -> None:
    app = create_app(session_token=_TEST_TOKEN, settings=initialized_settings)
    client = TestClient(app)
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect(f"/api/v1/stream?token={_TEST_TOKEN}&session=ghost"),
    ):
        pass


def test_ws_accepts_valid_token_and_session_then_delivers_frame(
    authed_client_and_session: tuple[TestClient, str],
) -> None:
    client, session_id = authed_client_and_session
    app = client.app

    with client.websocket_connect(f"/api/v1/stream?token={_TEST_TOKEN}&session={session_id}") as ws:
        # Server-side publish (simulates a router posting a progress
        # frame mid-operation).
        hub: StreamHub = app.state.stream_hub  # type: ignore[attr-defined]
        # The subscribe coroutine in the WS handler may not have
        # populated the hub yet on the very first frame; retry a few
        # times before giving up.
        delivered = 0
        for _ in range(20):
            delivered = hub.publish(
                session_id,
                StreamFrame("done", "op-7", {"result": {"ok": True}}),
            )
            if delivered > 0:
                break
            import time as _time

            _time.sleep(0.05)
        assert delivered > 0, "WS handler never registered with the hub"

        frame = ws.receive_json()
        assert frame["event"] == "done"
        assert frame["operation_id"] == "op-7"
        assert frame["result"] == {"ok": True}
