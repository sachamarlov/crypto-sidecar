"""Integration tests for :mod:`guardiabox.persistence.database`.

Exercise the async engine + session scope against an in-memory SQLite
database. The repository layer will rely on these primitives, so we
pin the expected contract here fail-fast.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from guardiabox.persistence.database import create_engine, session_scope, sqlcipher_available
from guardiabox.persistence.models import Base, User


@pytest.fixture(name="engine")
async def _engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


def _fake_user(username_hmac: bytes, uid: str) -> User:
    return User(
        id=uid,
        username_enc=b"\x00" * 28,
        username_hmac=username_hmac,
        salt=b"\x00" * 16,
        kdf_id=1,
        kdf_params=b"\x00\x09\x27\xc0",
        wrapped_vault_key=b"\x00" * 48,
        wrapped_rsa_private=b"\x00" * 256,
        rsa_public_pem=b"-----BEGIN PUBLIC KEY-----\n\n-----END PUBLIC KEY-----\n",
        created_at=datetime.now(UTC),
    )


async def _add_then_raise(engine: AsyncEngine, uid: str) -> None:
    """Helper kept out of pytest.raises so the block stays a one-liner."""
    async with session_scope(engine) as session:
        session.add(_fake_user(b"\x02" * 32, uid))
        raise RuntimeError("boom")


@pytest.mark.integration
async def test_session_scope_commits_on_success(engine: AsyncEngine) -> None:
    """An uncaught exception rolls back; clean exit commits."""
    async with session_scope(engine) as session:
        session.add(_fake_user(b"\x01" * 32, "u-1"))

    async with session_scope(engine) as session:
        result = await session.execute(select(User).where(User.id == "u-1"))
        fetched = result.scalar_one()
        assert fetched.username_hmac == b"\x01" * 32


@pytest.mark.integration
async def test_session_scope_rolls_back_on_exception(engine: AsyncEngine) -> None:
    """A raised exception must undo all staged changes."""
    with pytest.raises(RuntimeError, match="boom"):
        await _add_then_raise(engine, "u-2")

    async with session_scope(engine) as session:
        result = await session.execute(select(User).where(User.id == "u-2"))
        assert result.scalar_one_or_none() is None


@pytest.mark.integration
def test_create_engine_rejects_non_aiosqlite_url() -> None:
    with pytest.raises(ValueError, match="aiosqlite"):
        create_engine("sqlite:///tmp.db")


@pytest.mark.integration
async def test_create_engine_accepts_file_url(tmp_path: Path) -> None:
    """A filesystem URL spins up without crashing (no DDL yet)."""
    db_path = tmp_path / "vault.db"
    engine = create_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        assert db_path.exists()
    finally:
        await engine.dispose()


def test_sqlcipher_availability_probe_returns_bool() -> None:
    """The probe is purely informational and never raises."""
    assert isinstance(sqlcipher_available(), bool)
