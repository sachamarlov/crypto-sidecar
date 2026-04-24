"""SQLAlchemy 2.0 declarative models for the multi-user vault.

Schema invariants
-----------------

* **Encrypted columns** use :func:`guardiabox.core.crypto.encrypt_column`
  at the repository boundary. They are stored as ``BLOB`` (``LargeBinary``)
  and named with an ``_enc`` suffix.
* **Index companions** for encrypted columns carry an ``_hmac`` suffix and
  hold the deterministic HMAC-SHA256 tag produced by
  :func:`guardiabox.core.crypto.deterministic_index_hmac`. Equality
  lookups (``WHERE filename_hmac = ?``) run against those indices.
* **Audit log** is append-only: an AFTER-UPDATE/DELETE trigger fires an
  SQL error on any mutation of an existing row (installed by the
  initial Alembic migration, not by SQLAlchemy itself).
* **Hash chain**: each ``AuditEntry.entry_hash`` is
  ``SHA-256(prev_hash || canonical_json(columns_except_entry_hash))``.
  Verification walks the table in sequence order and fails on the
  first row whose computed hash differs from the stored one
  (cf. :mod:`guardiabox.security.audit`).

Why encrypt usernames on disk?
------------------------------

The academic brief covers one machine, but the DB file can still leak
onto a backup disk or an OS-level restore. We encrypt ``username`` so
``sqlite3 vault.db "select * from users"`` from outside the app does
not reveal the user list. Lookups go through the HMAC index.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

__all__ = [
    "AUDIT_HASH_BYTES",
    "AuditEntry",
    "Base",
    "Share",
    "User",
    "VaultItem",
]

#: Width of every hash in the audit chain (SHA-256 output).
AUDIT_HASH_BYTES: Final[int] = 32

#: Genesis hash used as ``prev_hash`` of the first audit entry.
AUDIT_GENESIS_HASH: Final[bytes] = b"\x00" * AUDIT_HASH_BYTES


class Base(DeclarativeBase):
    """Declarative base for every GuardiaBox ORM model.

    No shared columns — each concrete model declares its own ``id`` /
    primary key. The base exists only to share metadata with Alembic.
    """


class User(Base):
    """A locally registered vault user.

    Every secret-bearing column is wrapped with
    :func:`guardiabox.core.crypto.encrypt_column` except ``salt`` and
    ``kdf_*`` which are KDF parameters (public by design — they only
    make sense paired with the password).
    """

    __tablename__ = "users"

    # UUID hex (32 chars); keeping it as ``str`` lets us round-trip
    # through JSON / HTTP without encoding quirks.
    id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # Encrypted username + HMAC index for login lookup.
    username_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    username_hmac: Mapped[bytes] = mapped_column(
        LargeBinary(32),
        unique=True,
        index=True,
        nullable=False,
    )

    # KDF salt + parameters: public. Master key = KDF(password, salt, params).
    salt: Mapped[bytes] = mapped_column(LargeBinary(16), nullable=False)
    kdf_id: Mapped[int] = mapped_column(Integer, nullable=False)
    kdf_params: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Key material, each wrapped (AES-GCM) under the master key.
    wrapped_vault_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_rsa_private: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # RSA public key (PEM); public by design.
    rsa_public_pem: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Timestamps use timezone-aware UTC.
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_unlock_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    failed_unlock_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_unlock_last_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )

    # Eager relationships are opt-in via explicit select() calls; lazy="raise"
    # fires a runtime error rather than issuing a silent second query.
    vault_items: Mapped[list[VaultItem]] = relationship(
        back_populates="owner",
        lazy="raise",
        cascade="all, delete-orphan",
    )


class VaultItem(Base):
    """One encrypted payload (``.crypt`` file) owned by a user."""

    __tablename__ = "vault_items"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Encrypted filename + HMAC index for "do I already have this file?" queries.
    filename_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    filename_hmac: Mapped[bytes] = mapped_column(LargeBinary(32), index=True, nullable=False)

    # Encrypted original path on disk (``/Users/alice/Documents/report.pdf``
    # style). No HMAC index — never looked up by value.
    original_path_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # Non-sensitive metadata: where the .crypt lives + integrity.
    container_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    ciphertext_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    ciphertext_size: Mapped[int] = mapped_column(Integer, nullable=False)
    kdf_id: Mapped[int] = mapped_column(Integer, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    owner: Mapped[User] = relationship(back_populates="vault_items", lazy="raise")

    # A given owner cannot have two items with the same filename_hmac --
    # that would mean two stored files with the exact same name, which we
    # consider a user error worth surfacing fail-fast.
    __table_args__ = (
        UniqueConstraint("owner_user_id", "filename_hmac", name="uq_vaultitem_owner_filename"),
    )


class Share(Base):
    """A share token handing a vault item from one user to another (spec 003).

    The sender wraps the file's DEK under the recipient's RSA-OAEP
    public key and signs the bundle with their own RSA-PSS private key
    (cf. ADR-0004). This model holds the persisted trace of that
    exchange so the audit log can reconstruct it later.
    """

    __tablename__ = "shares"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    vault_item_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("vault_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sender_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    recipient_user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # DEK wrapped under recipient's RSA-OAEP public key.
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Sender RSA-PSS signature over (vault_item_id || wrapped_dek) — the
    # recipient verifies this before trusting the wrapped_dek.
    sender_signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )


class AuditEntry(Base):
    """One row of the append-only hash-chained audit log.

    Mutations (UPDATE / DELETE) are rejected by an AFTER-trigger
    installed in the initial Alembic migration. Verification is a
    single linear pass that recomputes ``entry_hash`` from
    ``prev_hash || canonical_json(...)`` and compares byte-for-byte.
    """

    __tablename__ = "audit_log"

    # Auto-incrementing sequence; gaps must never occur (the trigger
    # prevents DELETE entirely).
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Nullable: some actions (system migration, boot, ...) have no actor.
    actor_user_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # StrEnum value from :class:`guardiabox.security.audit.AuditAction`.
    # Stored as VARCHAR so a future unknown action survives a read.
    action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    # Encrypted target (filename, share id, ...). Indexed via HMAC.
    target_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    target_hmac: Mapped[bytes | None] = mapped_column(LargeBinary(32), index=True, nullable=True)

    # Encrypted JSON metadata blob (action-specific key/value pairs).
    metadata_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # Hash-chain fields. Both exactly 32 bytes (SHA-256 output).
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary(AUDIT_HASH_BYTES), nullable=False)
    entry_hash: Mapped[bytes] = mapped_column(LargeBinary(AUDIT_HASH_BYTES), nullable=False)
