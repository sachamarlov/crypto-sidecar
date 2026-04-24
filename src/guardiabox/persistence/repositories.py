"""Repository pattern — typed, async access to the persistence layer.

Each repository owns one aggregate (:class:`User`, :class:`VaultItem`,
:class:`Share`, :class:`AuditEntry`) and hides the SQLAlchemy-specific
query details behind a narrow method surface. Callers depend on the
public methods here; they never construct ``select(...)`` directly.

Two keys flow through the surface:

* ``vault_admin_key`` — a 32-byte AES key derived from the vault
  administrator password. Every repository that reads or writes an
  encrypted column needs it. The key travels in memory only; callers
  drop it from their own buffers when the session ends.
* ``actor_user_id`` — the acting user's ``User.id`` (or ``None`` for
  system events). AuditRepository records it; the other repositories
  pass it through only when audit hooks fire downstream.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from guardiabox.core.crypto import (
    decrypt_column,
    deterministic_index_hmac,
    encrypt_column,
)
from guardiabox.persistence.models import AuditEntry, Share, User, VaultItem

__all__ = [
    "AuditRepository",
    "ShareRepository",
    "UserRepository",
    "VaultItemRepository",
]

#: Column names used as AAD in encrypt_column / deterministic_index_hmac.
#: Stored as constants so any typo (``"usernam"``) fails import, not runtime.
_COL_USERNAME: Final[str] = "users.username"
_COL_VAULT_FILENAME: Final[str] = "vault_items.filename"
_COL_VAULT_ORIGINAL_PATH: Final[str] = "vault_items.original_path"
_COL_AUDIT_TARGET: Final[str] = "audit_log.target"
_COL_AUDIT_METADATA: Final[str] = "audit_log.metadata"


# ---------------------------------------------------------------------------
# UserRepository
# ---------------------------------------------------------------------------


class UserRepository:
    """CRUD + lockout helpers for :class:`User`."""

    def __init__(self, session: AsyncSession, vault_admin_key: bytes) -> None:
        self._session = session
        self._key = vault_admin_key

    async def get_by_username(self, username: str) -> User | None:
        """Return the user whose ``username_hmac`` matches ``username``."""
        hmac_tag = deterministic_index_hmac(
            self._key, column=_COL_USERNAME, plaintext=username.encode("utf-8")
        )
        result = await self._session.execute(select(User).where(User.username_hmac == hmac_tag))
        return result.scalar_one_or_none()

    def decrypt_username(self, user: User) -> str:
        """Return the decrypted UTF-8 username of ``user``."""
        plaintext = decrypt_column(
            user.username_enc, self._key, column=_COL_USERNAME, row_id=user.id.encode("utf-8")
        )
        return plaintext.decode("utf-8")

    async def list_all(self) -> Sequence[User]:
        result = await self._session.execute(select(User))
        return result.scalars().all()

    async def create(
        self,
        *,
        user_id: str,
        username: str,
        salt: bytes,
        kdf_id: int,
        kdf_params: bytes,
        wrapped_vault_key: bytes,
        wrapped_rsa_private: bytes,
        rsa_public_pem: bytes,
    ) -> User:
        """Insert a new user row; return the populated ORM instance.

        ``username`` is encrypted under the vault admin key with AAD
        bound to ``users.username`` and the user's id, plus a
        deterministic HMAC index for login lookups.
        """
        username_bytes = username.encode("utf-8")
        now = datetime.now(UTC)
        user = User(
            id=user_id,
            username_enc=encrypt_column(
                username_bytes,
                self._key,
                column=_COL_USERNAME,
                row_id=user_id.encode("utf-8"),
            ),
            username_hmac=deterministic_index_hmac(
                self._key, column=_COL_USERNAME, plaintext=username_bytes
            ),
            salt=salt,
            kdf_id=kdf_id,
            kdf_params=kdf_params,
            wrapped_vault_key=wrapped_vault_key,
            wrapped_rsa_private=wrapped_rsa_private,
            rsa_public_pem=rsa_public_pem,
            created_at=now,
        )
        self._session.add(user)
        await self._session.flush()
        return user

    async def delete(self, user_id: str) -> None:
        user = await self._session.get(User, user_id)
        if user is not None:
            await self._session.delete(user)

    async def record_unlock_success(self, user: User, *, when: datetime | None = None) -> None:
        user.last_unlock_at = when or datetime.now(UTC)
        user.failed_unlock_count = 0
        user.failed_unlock_last_at = None
        await self._session.flush()

    async def record_unlock_failure(self, user: User, *, when: datetime | None = None) -> None:
        user.failed_unlock_count = (user.failed_unlock_count or 0) + 1
        user.failed_unlock_last_at = when or datetime.now(UTC)
        await self._session.flush()


# ---------------------------------------------------------------------------
# VaultItemRepository
# ---------------------------------------------------------------------------


class VaultItemRepository:
    """CRUD for :class:`VaultItem` with transparent column encryption."""

    def __init__(self, session: AsyncSession, vault_admin_key: bytes) -> None:
        self._session = session
        self._key = vault_admin_key

    async def create(
        self,
        *,
        item_id: str,
        owner_user_id: str,
        filename: str,
        original_path: str | None,
        container_path: str,
        ciphertext_sha256: bytes,
        ciphertext_size: int,
        kdf_id: int,
    ) -> VaultItem:
        """Insert a new vault item, encrypting sensitive columns first."""
        filename_bytes = filename.encode("utf-8")
        now = datetime.now(UTC)
        item = VaultItem(
            id=item_id,
            owner_user_id=owner_user_id,
            filename_enc=encrypt_column(
                filename_bytes,
                self._key,
                column=_COL_VAULT_FILENAME,
                row_id=item_id.encode("utf-8"),
            ),
            filename_hmac=deterministic_index_hmac(
                self._key, column=_COL_VAULT_FILENAME, plaintext=filename_bytes
            ),
            original_path_enc=(
                encrypt_column(
                    original_path.encode("utf-8"),
                    self._key,
                    column=_COL_VAULT_ORIGINAL_PATH,
                    row_id=item_id.encode("utf-8"),
                )
                if original_path is not None
                else None
            ),
            container_path=container_path,
            ciphertext_sha256=ciphertext_sha256,
            ciphertext_size=ciphertext_size,
            kdf_id=kdf_id,
            created_at=now,
            updated_at=now,
        )
        self._session.add(item)
        await self._session.flush()
        return item

    async def get(self, item_id: str) -> VaultItem | None:
        return await self._session.get(VaultItem, item_id)

    async def list_for_owner(self, owner_user_id: str) -> Sequence[VaultItem]:
        result = await self._session.execute(
            select(VaultItem).where(VaultItem.owner_user_id == owner_user_id)
        )
        return result.scalars().all()

    async def find_by_filename(self, *, owner_user_id: str, filename: str) -> VaultItem | None:
        hmac_tag = deterministic_index_hmac(
            self._key,
            column=_COL_VAULT_FILENAME,
            plaintext=filename.encode("utf-8"),
        )
        result = await self._session.execute(
            select(VaultItem).where(
                VaultItem.owner_user_id == owner_user_id,
                VaultItem.filename_hmac == hmac_tag,
            )
        )
        return result.scalar_one_or_none()

    def decrypt_filename(self, item: VaultItem) -> str:
        return decrypt_column(
            item.filename_enc,
            self._key,
            column=_COL_VAULT_FILENAME,
            row_id=item.id.encode("utf-8"),
        ).decode("utf-8")

    def decrypt_original_path(self, item: VaultItem) -> str | None:
        if item.original_path_enc is None:
            return None
        return decrypt_column(
            item.original_path_enc,
            self._key,
            column=_COL_VAULT_ORIGINAL_PATH,
            row_id=item.id.encode("utf-8"),
        ).decode("utf-8")

    async def delete(self, item_id: str) -> None:
        item = await self._session.get(VaultItem, item_id)
        if item is not None:
            await self._session.delete(item)


# ---------------------------------------------------------------------------
# ShareRepository (minimal — spec 003 lands the full flow)
# ---------------------------------------------------------------------------


class ShareRepository:
    """Persistence for :class:`Share` tokens.

    Phase C ships the CRUD surface; spec 003 (phase D) adds the
    wrap / sign / verify logic that produces ``wrapped_dek`` and
    ``sender_signature``.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        share_id: str,
        vault_item_id: str,
        sender_user_id: str,
        recipient_user_id: str,
        wrapped_dek: bytes,
        sender_signature: bytes,
        expires_at: datetime | None = None,
    ) -> Share:
        share = Share(
            id=share_id,
            vault_item_id=vault_item_id,
            sender_user_id=sender_user_id,
            recipient_user_id=recipient_user_id,
            wrapped_dek=wrapped_dek,
            sender_signature=sender_signature,
            created_at=datetime.now(UTC),
            expires_at=expires_at,
        )
        self._session.add(share)
        await self._session.flush()
        return share

    async def get(self, share_id: str) -> Share | None:
        return await self._session.get(Share, share_id)

    async def list_incoming(self, recipient_user_id: str) -> Sequence[Share]:
        result = await self._session.execute(
            select(Share).where(Share.recipient_user_id == recipient_user_id)
        )
        return result.scalars().all()

    async def list_outgoing(self, sender_user_id: str) -> Sequence[Share]:
        result = await self._session.execute(
            select(Share).where(Share.sender_user_id == sender_user_id)
        )
        return result.scalars().all()

    async def mark_accepted(self, share_id: str) -> None:
        share = await self._session.get(Share, share_id)
        if share is not None:
            share.accepted_at = datetime.now(UTC)
            await self._session.flush()


# ---------------------------------------------------------------------------
# AuditRepository
# ---------------------------------------------------------------------------


class AuditRepository:
    """Read / insert access on the append-only audit log.

    The actual hash-chain append logic lives in
    :mod:`guardiabox.security.audit` so the chain invariant stays in
    one module. This repository exposes the lower-level INSERT + the
    filtered read queries that the CLI ``history`` command drives.
    """

    def __init__(self, session: AsyncSession, vault_admin_key: bytes) -> None:
        self._session = session
        self._key = vault_admin_key

    async def insert_row(self, entry: AuditEntry) -> AuditEntry:
        """Append a pre-built AuditEntry. Trigger keeps the table append-only."""
        self._session.add(entry)
        await self._session.flush()
        return entry

    async def latest(self) -> AuditEntry | None:
        """Return the row with the highest ``sequence`` (None if empty)."""
        result = await self._session.execute(
            select(AuditEntry).order_by(AuditEntry.sequence.desc()).limit(1)
        )
        return result.scalar_one_or_none()

    async def all_in_order(self) -> Sequence[AuditEntry]:
        """Return every entry in ascending sequence order.

        Used by :func:`guardiabox.security.audit.verify` to walk the
        hash chain from genesis forward.
        """
        result = await self._session.execute(select(AuditEntry).order_by(AuditEntry.sequence.asc()))
        return result.scalars().all()

    async def list_filtered(
        self,
        *,
        actor_user_id: str | None = None,
        action: str | None = None,
        limit: int = 100,
    ) -> Sequence[AuditEntry]:
        """Return audit rows matching the given filters, most recent first."""
        stmt = select(AuditEntry)
        if actor_user_id is not None:
            stmt = stmt.where(AuditEntry.actor_user_id == actor_user_id)
        if action is not None:
            stmt = stmt.where(AuditEntry.action == action)
        stmt = stmt.order_by(AuditEntry.sequence.desc()).limit(limit)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    def encrypt_target(self, target: str, *, sequence: int) -> tuple[bytes, bytes]:
        """Return ``(target_enc, target_hmac)`` for a plaintext target string."""
        target_bytes = target.encode("utf-8")
        target_enc = encrypt_column(
            target_bytes,
            self._key,
            column=_COL_AUDIT_TARGET,
            row_id=str(sequence).encode("utf-8"),
        )
        target_hmac = deterministic_index_hmac(
            self._key, column=_COL_AUDIT_TARGET, plaintext=target_bytes
        )
        return target_enc, target_hmac

    def encrypt_metadata(self, metadata_json: bytes, *, sequence: int) -> bytes:
        return encrypt_column(
            metadata_json,
            self._key,
            column=_COL_AUDIT_METADATA,
            row_id=str(sequence).encode("utf-8"),
        )

    def decrypt_target(self, entry: AuditEntry) -> str | None:
        if entry.target_enc is None:
            return None
        return decrypt_column(
            entry.target_enc,
            self._key,
            column=_COL_AUDIT_TARGET,
            row_id=str(entry.sequence).encode("utf-8"),
        ).decode("utf-8")

    def decrypt_metadata(self, entry: AuditEntry) -> bytes | None:
        if entry.metadata_enc is None:
            return None
        return decrypt_column(
            entry.metadata_enc,
            self._key,
            column=_COL_AUDIT_METADATA,
            row_id=str(entry.sequence).encode("utf-8"),
        )
