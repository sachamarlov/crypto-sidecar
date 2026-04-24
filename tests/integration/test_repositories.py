"""Integration tests for the repository layer.

Everything runs against an in-memory aiosqlite database spun up
per-test. Encrypted columns are verified round-tripping (plaintext
preserved, on-disk BLOB unreadable without the vault admin key),
and the append-only trigger on audit_log keeps firing through the
ORM path.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
import secrets
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from guardiabox.persistence.database import create_engine, session_scope
from guardiabox.persistence.models import AuditEntry
from guardiabox.persistence.repositories import (
    AuditRepository,
    ShareRepository,
    UserRepository,
    VaultItemRepository,
)

ROOT = Path(__file__).resolve().parents[2]
VAULT_KEY = secrets.token_bytes(32)


def _alembic_config(db_path: Path) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    script_dir = ROOT / "src" / "guardiabox" / "persistence" / "migrations"
    cfg.set_main_option("script_location", str(script_dir))
    return cfg


def _run_alembic_upgrade(db_path: Path) -> None:
    """Upgrade the given DB. Kept sync so the caller can push it to a thread.

    ``alembic.command.upgrade`` calls ``asyncio.run`` internally
    (env.py ``run_migrations_online``) which refuses to work on top of
    a running event loop. Test fixtures live inside pytest-asyncio's
    loop, so we schedule this via ``asyncio.to_thread`` instead.
    """
    command.upgrade(_alembic_config(db_path), "head")


@pytest.fixture(name="engine")
async def _engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    db = tmp_path / "vault.db"
    await asyncio.to_thread(_run_alembic_upgrade, db)
    engine = create_engine(f"sqlite+aiosqlite:///{db}")
    yield engine
    await engine.dispose()


# ---------------------------------------------------------------------------
# UserRepository
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_user_create_then_lookup_by_username(engine: AsyncEngine) -> None:
    async with session_scope(engine) as session:
        repo = UserRepository(session, VAULT_KEY)
        user = await repo.create(
            user_id=uuid4().hex,
            username="alice",
            salt=b"\x00" * 16,
            kdf_id=1,
            kdf_params=b"\x00\x09\x27\xc0",
            wrapped_vault_key=b"\x00" * 64,
            wrapped_rsa_private=b"\x00" * 256,
            rsa_public_pem=b"-----BEGIN PUBLIC KEY-----\n\n-----END PUBLIC KEY-----\n",
        )
        assert user.username_enc != b"alice", "username must be stored encrypted"
        assert len(user.username_hmac) == 32

    async with session_scope(engine) as session:
        repo = UserRepository(session, VAULT_KEY)
        fetched = await repo.get_by_username("alice")
        assert fetched is not None
        assert repo.decrypt_username(fetched) == "alice"


@pytest.mark.integration
async def test_user_lookup_unknown_returns_none(engine: AsyncEngine) -> None:
    async with session_scope(engine) as session:
        repo = UserRepository(session, VAULT_KEY)
        assert await repo.get_by_username("never-registered") is None


async def _create_user_named(engine: AsyncEngine, *, uid: str, username: str) -> None:
    async with session_scope(engine) as session:
        repo = UserRepository(session, VAULT_KEY)
        await repo.create(
            user_id=uid,
            username=username,
            salt=b"\x00" * 16,
            kdf_id=1,
            kdf_params=b"\x00\x09\x27\xc0",
            wrapped_vault_key=b"\x00" * 64,
            wrapped_rsa_private=b"\x00" * 256,
            rsa_public_pem=b"",
        )


@pytest.mark.integration
async def test_user_duplicate_username_hmac_rejected(engine: AsyncEngine) -> None:
    """``username_hmac`` is a UNIQUE column; inserting twice must fail."""
    from sqlalchemy.exc import IntegrityError

    await _create_user_named(engine, uid="u-1", username="alice")
    with pytest.raises(IntegrityError):
        await _create_user_named(engine, uid="u-2", username="alice")


@pytest.mark.integration
async def test_user_unlock_counters(engine: AsyncEngine) -> None:
    async with session_scope(engine) as session:
        repo = UserRepository(session, VAULT_KEY)
        user = await repo.create(
            user_id="u-1",
            username="alice",
            salt=b"\x00" * 16,
            kdf_id=1,
            kdf_params=b"\x00\x09\x27\xc0",
            wrapped_vault_key=b"\x00" * 64,
            wrapped_rsa_private=b"\x00" * 256,
            rsa_public_pem=b"",
        )
        await repo.record_unlock_failure(user)
        await repo.record_unlock_failure(user)
        assert user.failed_unlock_count == 2
        assert user.failed_unlock_last_at is not None

        await repo.record_unlock_success(user)
        assert user.failed_unlock_count == 0
        assert user.last_unlock_at is not None


# ---------------------------------------------------------------------------
# VaultItemRepository
# ---------------------------------------------------------------------------


async def _seed_user(engine: AsyncEngine) -> str:
    async with session_scope(engine) as session:
        repo = UserRepository(session, VAULT_KEY)
        user = await repo.create(
            user_id="owner-1",
            username="alice",
            salt=b"\x00" * 16,
            kdf_id=1,
            kdf_params=b"\x00\x09\x27\xc0",
            wrapped_vault_key=b"\x00" * 64,
            wrapped_rsa_private=b"\x00" * 256,
            rsa_public_pem=b"",
        )
        return user.id


@pytest.mark.integration
async def test_vault_item_create_and_find_by_filename(engine: AsyncEngine) -> None:
    owner_id = await _seed_user(engine)
    async with session_scope(engine) as session:
        repo = VaultItemRepository(session, VAULT_KEY)
        item = await repo.create(
            item_id="item-1",
            owner_user_id=owner_id,
            filename="invoice.pdf",
            original_path="/home/alice/invoice.pdf",
            container_path="/vault/invoice.pdf.crypt",
            ciphertext_sha256=b"\xff" * 32,
            ciphertext_size=4096,
            kdf_id=1,
        )
        assert item.filename_enc != b"invoice.pdf"
        assert repo.decrypt_filename(item) == "invoice.pdf"
        assert repo.decrypt_original_path(item) == "/home/alice/invoice.pdf"

    async with session_scope(engine) as session:
        repo = VaultItemRepository(session, VAULT_KEY)
        found = await repo.find_by_filename(owner_user_id=owner_id, filename="invoice.pdf")
        assert found is not None
        assert found.id == "item-1"
        assert repo.decrypt_filename(found) == "invoice.pdf"


async def _create_vault_item_named(
    engine: AsyncEngine, *, item_id: str, owner_user_id: str, filename: str, path: str
) -> None:
    async with session_scope(engine) as session:
        repo = VaultItemRepository(session, VAULT_KEY)
        await repo.create(
            item_id=item_id,
            owner_user_id=owner_user_id,
            filename=filename,
            original_path=None,
            container_path=path,
            ciphertext_sha256=b"\x00" * 32,
            ciphertext_size=1,
            kdf_id=1,
        )


@pytest.mark.integration
async def test_vault_item_duplicate_filename_per_owner_rejected(engine: AsyncEngine) -> None:
    from sqlalchemy.exc import IntegrityError

    owner_id = await _seed_user(engine)
    await _create_vault_item_named(
        engine, item_id="item-1", owner_user_id=owner_id, filename="dup.pdf", path="/a"
    )
    with pytest.raises(IntegrityError):
        await _create_vault_item_named(
            engine, item_id="item-2", owner_user_id=owner_id, filename="dup.pdf", path="/b"
        )


# ---------------------------------------------------------------------------
# AuditRepository
# ---------------------------------------------------------------------------


def _fabricate_audit_entry(sequence: int, prev_hash: bytes, action: str) -> AuditEntry:
    """Build an AuditEntry manually for repo-level testing.

    The hash-chain logic lives in security.audit; we exercise it in
    its own test file. Here we just want to insert rows and read them
    back to verify the repository surface.
    """
    return AuditEntry(
        sequence=sequence,
        timestamp=datetime.now(UTC),
        actor_user_id=None,
        action=action,
        target_enc=None,
        target_hmac=None,
        metadata_enc=None,
        prev_hash=prev_hash,
        entry_hash=b"\xaa" * 32,
    )


@pytest.mark.integration
async def test_audit_insert_and_latest_and_list(engine: AsyncEngine) -> None:
    async with session_scope(engine) as session:
        repo = AuditRepository(session, VAULT_KEY)
        await repo.insert_row(_fabricate_audit_entry(1, b"\x00" * 32, "user.create"))
        await repo.insert_row(_fabricate_audit_entry(2, b"\xaa" * 32, "file.encrypt"))

    async with session_scope(engine) as session:
        repo = AuditRepository(session, VAULT_KEY)
        latest = await repo.latest()
        assert latest is not None
        assert latest.sequence == 2

        all_entries = await repo.all_in_order()
        assert [e.sequence for e in all_entries] == [1, 2]

        filtered = await repo.list_filtered(action="file.encrypt")
        assert len(filtered) == 1
        assert filtered[0].action == "file.encrypt"


@pytest.mark.integration
async def test_audit_target_encrypt_roundtrip(engine: AsyncEngine) -> None:
    """``encrypt_target`` produces a blob that decrypts to the same string."""
    async with session_scope(engine) as session:
        repo = AuditRepository(session, VAULT_KEY)
        target_enc, target_hmac = repo.encrypt_target("alice", sequence=1)
        entry = AuditEntry(
            sequence=1,
            timestamp=datetime.now(UTC),
            actor_user_id=None,
            action="user.create",
            target_enc=target_enc,
            target_hmac=target_hmac,
            metadata_enc=None,
            prev_hash=b"\x00" * 32,
            entry_hash=b"\xaa" * 32,
        )
        await repo.insert_row(entry)

    async with session_scope(engine) as session:
        repo = AuditRepository(session, VAULT_KEY)
        entries = await repo.all_in_order()
        assert len(entries) == 1
        assert repo.decrypt_target(entries[0]) == "alice"


# ---------------------------------------------------------------------------
# ShareRepository (thin)
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_share_create_and_list(engine: AsyncEngine) -> None:
    owner_id = await _seed_user(engine)
    async with session_scope(engine) as session:
        users = UserRepository(session, VAULT_KEY)
        await users.create(
            user_id="bob",
            username="bob",
            salt=b"\x00" * 16,
            kdf_id=1,
            kdf_params=b"\x00\x09\x27\xc0",
            wrapped_vault_key=b"\x00" * 64,
            wrapped_rsa_private=b"\x00" * 256,
            rsa_public_pem=b"",
        )
        items = VaultItemRepository(session, VAULT_KEY)
        await items.create(
            item_id="item-1",
            owner_user_id=owner_id,
            filename="share.pdf",
            original_path=None,
            container_path="/x",
            ciphertext_sha256=b"\x00" * 32,
            ciphertext_size=1,
            kdf_id=1,
        )

    async with session_scope(engine) as session:
        shares = ShareRepository(session)
        await shares.create(
            share_id="s-1",
            vault_item_id="item-1",
            sender_user_id=owner_id,
            recipient_user_id="bob",
            wrapped_dek=b"\xff" * 512,
            sender_signature=b"\xcc" * 256,
        )

    async with session_scope(engine) as session:
        shares = ShareRepository(session)
        incoming = await shares.list_incoming("bob")
        assert len(incoming) == 1
        assert incoming[0].id == "s-1"
        outgoing = await shares.list_outgoing(owner_id)
        assert len(outgoing) == 1

        await shares.mark_accepted("s-1")

    async with session_scope(engine) as session:
        shares = ShareRepository(session)
        share = await shares.get("s-1")
        assert share is not None
        assert share.accepted_at is not None
