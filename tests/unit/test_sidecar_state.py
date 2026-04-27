"""Unit tests for the sidecar SessionStore (G-03)."""

from __future__ import annotations

import pytest

from guardiabox.ui.tauri.sidecar.state import SessionStore, _zero_fill


def test_open_admin_session_returns_unique_id() -> None:
    store = SessionStore(ttl_seconds=60.0)

    s1 = store.open_admin_session(b"\x01" * 32)
    s2 = store.open_admin_session(b"\x02" * 32)

    assert s1.session_id != s2.session_id
    assert len(store) == 2


def test_open_admin_session_rejects_empty_key() -> None:
    store = SessionStore(ttl_seconds=60.0)
    with pytest.raises(ValueError, match="must not be empty"):
        store.open_admin_session(b"")


def test_get_returns_session_within_ttl() -> None:
    store = SessionStore(ttl_seconds=60.0)
    session = store.open_admin_session(b"\xaa" * 32)

    fetched = store.get(session.session_id)

    assert fetched is session


def test_get_returns_none_after_ttl_expiry() -> None:
    fake_now = [0.0]

    def clock() -> float:
        return fake_now[0]

    store = SessionStore(ttl_seconds=10.0, clock=clock)
    session = store.open_admin_session(b"\xaa" * 32)

    fake_now[0] = 11.0
    fetched = store.get(session.session_id)

    assert fetched is None
    assert len(store) == 0  # auto-reaped on access


def test_get_slides_expiry_on_access() -> None:
    fake_now = [0.0]

    def clock() -> float:
        return fake_now[0]

    store = SessionStore(ttl_seconds=10.0, clock=clock)
    session = store.open_admin_session(b"\xaa" * 32)

    fake_now[0] = 9.0
    assert store.get(session.session_id) is session
    # We accessed at t=9, expiry now t=19.
    fake_now[0] = 18.0
    assert store.get(session.session_id) is session
    fake_now[0] = 100.0
    assert store.get(session.session_id) is None


def test_close_zero_fills_admin_key() -> None:
    store = SessionStore(ttl_seconds=60.0)
    raw = b"\x77" * 32
    session = store.open_admin_session(raw)
    buf = session.admin_key  # capture the bytearray reference

    closed = store.close(session.session_id)

    assert closed is True
    # The buffer the store held was zero-filled before being dropped.
    assert all(b == 0 for b in buf)
    assert store.get(session.session_id) is None


def test_close_returns_false_for_unknown_session() -> None:
    store = SessionStore(ttl_seconds=60.0)
    assert store.close("does-not-exist") is False


def test_unlock_user_attaches_vault_key() -> None:
    store = SessionStore(ttl_seconds=60.0)
    session = store.open_admin_session(b"\x01" * 32)

    store.unlock_user(session.session_id, user_id="alice", vault_key=b"\x42" * 32)

    refreshed = store.get(session.session_id)
    assert refreshed is not None
    assert refreshed.user_unlocks["alice"] == bytearray(b"\x42" * 32)


def test_unlock_user_replaces_previous_zero_fills_old() -> None:
    store = SessionStore(ttl_seconds=60.0)
    session = store.open_admin_session(b"\x01" * 32)

    store.unlock_user(session.session_id, user_id="alice", vault_key=b"\x42" * 32)
    old_buf = session.user_unlocks["alice"]

    store.unlock_user(session.session_id, user_id="alice", vault_key=b"\x99" * 32)

    assert all(b == 0 for b in old_buf)
    assert session.user_unlocks["alice"] == bytearray(b"\x99" * 32)


def test_unlock_user_raises_on_unknown_session() -> None:
    store = SessionStore(ttl_seconds=60.0)
    with pytest.raises(KeyError, match="not found or expired"):
        store.unlock_user("ghost", user_id="alice", vault_key=b"\x01" * 32)


def test_lock_user_zero_fills_and_drops() -> None:
    store = SessionStore(ttl_seconds=60.0)
    session = store.open_admin_session(b"\x01" * 32)
    store.unlock_user(session.session_id, user_id="alice", vault_key=b"\x42" * 32)
    buf = session.user_unlocks["alice"]

    locked = store.lock_user(session.session_id, user_id="alice")

    assert locked is True
    assert all(b == 0 for b in buf)
    assert "alice" not in session.user_unlocks


def test_lock_user_returns_false_when_user_not_unlocked() -> None:
    store = SessionStore(ttl_seconds=60.0)
    session = store.open_admin_session(b"\x01" * 32)
    assert store.lock_user(session.session_id, user_id="alice") is False


def test_close_all_zero_fills_every_buffer() -> None:
    store = SessionStore(ttl_seconds=60.0)
    s1 = store.open_admin_session(b"\x11" * 32)
    s2 = store.open_admin_session(b"\x22" * 32)
    store.unlock_user(s2.session_id, user_id="alice", vault_key=b"\x42" * 32)
    user_buf = s2.user_unlocks["alice"]

    count = store.close_all()

    assert count == 2
    assert all(b == 0 for b in s1.admin_key)
    assert all(b == 0 for b in s2.admin_key)
    assert all(b == 0 for b in user_buf)
    assert len(store) == 0


def test_reap_expired_drops_only_expired() -> None:
    fake_now = [0.0]

    def clock() -> float:
        return fake_now[0]

    store = SessionStore(ttl_seconds=10.0, clock=clock)
    fresh = store.open_admin_session(b"\x01" * 32)

    fake_now[0] = 5.0
    young = store.open_admin_session(b"\x02" * 32)

    fake_now[0] = 12.0  # only `fresh` (expires_at=10) is past expiry.
    reaped = store.reap_expired()

    assert reaped == 1
    assert store.get(young.session_id) is young
    assert store.get(fresh.session_id) is None


def test_zero_fill_handles_empty_buffer() -> None:
    """Lock the helper invariant -- it must be a no-op on empty input."""
    buf = bytearray()
    _zero_fill(buf)
    assert buf == bytearray()


def test_invalid_ttl_rejected() -> None:
    with pytest.raises(ValueError, match="positive"):
        SessionStore(ttl_seconds=0.0)
    with pytest.raises(ValueError, match="positive"):
        SessionStore(ttl_seconds=-1.0)
