"""Smoke tests for the SQLAlchemy declarative models.

Focuses on schema invariants that Alembic and the repository layer
will rely on: column types, primary / foreign keys, uniqueness, and
that ``Base.metadata`` can generate DDL without raising.
"""

from __future__ import annotations

from sqlalchemy import create_engine

from guardiabox.persistence.models import (
    AUDIT_HASH_BYTES,
    AuditEntry,
    Base,
    Share,
    User,
    VaultItem,
)


def test_metadata_has_four_tables() -> None:
    """Exactly the four tables the spec requires are registered."""
    names = set(Base.metadata.tables.keys())
    assert names == {"users", "vault_items", "shares", "audit_log"}


def test_create_all_against_sqlite_memory() -> None:
    """``Base.metadata.create_all`` must emit valid SQLite DDL.

    This is a synchronous-driver smoke; the async path is exercised in
    the repository integration suite. If a column type is wrong (e.g.
    missing length on a String PK), SQLite raises here.
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    engine.dispose()


def test_user_has_expected_columns() -> None:
    cols = {c.name for c in User.__table__.columns}
    required = {
        "id",
        "username_enc",
        "username_hmac",
        "salt",
        "kdf_id",
        "kdf_params",
        "wrapped_vault_key",
        "wrapped_rsa_private",
        "rsa_public_pem",
        "created_at",
        "last_unlock_at",
        "failed_unlock_count",
        "failed_unlock_last_at",
    }
    missing = required - cols
    assert not missing, f"User model missing columns: {missing}"


def test_user_username_hmac_is_unique_and_indexed() -> None:
    col = User.__table__.c.username_hmac
    assert col.unique is True, "username_hmac must be unique for login lookups"
    assert col.index is True


def test_vault_item_filename_hmac_indexed() -> None:
    col = VaultItem.__table__.c.filename_hmac
    assert col.index is True


def test_vault_item_owner_filename_unique_per_owner() -> None:
    """The same owner cannot hold two items with the same filename_hmac."""
    constraints = {c.name for c in VaultItem.__table__.constraints if c.name is not None}
    assert "uq_vaultitem_owner_filename" in constraints


def test_vault_item_cascades_on_user_delete() -> None:
    """Deleting a User must cascade to their VaultItems."""
    fk = next(iter(VaultItem.__table__.c.owner_user_id.foreign_keys))
    assert fk.ondelete == "CASCADE"


def test_share_has_three_foreign_keys() -> None:
    fks = {fk.parent.name for fk in Share.__table__.foreign_keys}
    assert fks == {"vault_item_id", "sender_user_id", "recipient_user_id"}


def test_audit_entry_sequence_autoincrement() -> None:
    col = AuditEntry.__table__.c.sequence
    assert col.primary_key is True
    assert col.autoincrement is True


def test_audit_entry_hash_widths_are_sha256() -> None:
    assert AUDIT_HASH_BYTES == 32
    # LargeBinary column sizes on SQLite are advisory, but the constant
    # is the source of truth the repo layer will enforce.


def test_audit_entry_actor_nullable_with_set_null_on_delete() -> None:
    """System events keep their audit row even when the actor user is deleted."""
    col = AuditEntry.__table__.c.actor_user_id
    assert col.nullable is True
    fk = next(iter(col.foreign_keys))
    assert fk.ondelete == "SET NULL"


def test_models_are_importable_symbols() -> None:
    """The four public names surface through :mod:`guardiabox.persistence.models`."""
    import guardiabox.persistence.models as mod

    for name in ("User", "VaultItem", "Share", "AuditEntry", "Base"):
        assert hasattr(mod, name), f"missing export: {name}"
