"""Initial schema: users, vault_items, shares, audit_log.

Creates the four tables declared in :mod:`guardiabox.persistence.models`
and installs two SQLite triggers that make the audit_log table
append-only (``UPDATE`` and ``DELETE`` both raise an error).

Revision ID: 0001
Revises:
Create Date: 2026-04-24
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# ----------------------------------------------------------------------------
# DDL
# ----------------------------------------------------------------------------


def upgrade() -> None:
    """Create the four tables + append-only triggers on audit_log."""
    op.create_table(
        "users",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("username_enc", sa.LargeBinary, nullable=False),
        sa.Column("username_hmac", sa.LargeBinary(32), nullable=False),
        sa.Column("salt", sa.LargeBinary(16), nullable=False),
        sa.Column("kdf_id", sa.Integer, nullable=False),
        sa.Column("kdf_params", sa.LargeBinary, nullable=False),
        sa.Column("wrapped_vault_key", sa.LargeBinary, nullable=False),
        sa.Column("wrapped_rsa_private", sa.LargeBinary, nullable=False),
        sa.Column("rsa_public_pem", sa.LargeBinary, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_unlock_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_unlock_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("failed_unlock_last_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("username_hmac", name="uq_users_username_hmac"),
    )
    op.create_index("ix_users_username_hmac", "users", ["username_hmac"], unique=True)

    op.create_table(
        "vault_items",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "owner_user_id",
            sa.String(64),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("filename_enc", sa.LargeBinary, nullable=False),
        sa.Column("filename_hmac", sa.LargeBinary(32), nullable=False),
        sa.Column("original_path_enc", sa.LargeBinary, nullable=True),
        sa.Column("container_path", sa.String(1024), nullable=False),
        sa.Column("ciphertext_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("ciphertext_size", sa.Integer, nullable=False),
        sa.Column("kdf_id", sa.Integer, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("owner_user_id", "filename_hmac", name="uq_vaultitem_owner_filename"),
    )
    op.create_index("ix_vault_items_owner_user_id", "vault_items", ["owner_user_id"])
    op.create_index("ix_vault_items_filename_hmac", "vault_items", ["filename_hmac"])

    op.create_table(
        "shares",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "vault_item_id",
            sa.String(64),
            sa.ForeignKey("vault_items.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "sender_user_id",
            sa.String(64),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "recipient_user_id",
            sa.String(64),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("wrapped_dek", sa.LargeBinary, nullable=False),
        sa.Column("sender_signature", sa.LargeBinary, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_shares_vault_item_id", "shares", ["vault_item_id"])
    op.create_index("ix_shares_sender_user_id", "shares", ["sender_user_id"])
    op.create_index("ix_shares_recipient_user_id", "shares", ["recipient_user_id"])

    op.create_table(
        "audit_log",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "actor_user_id",
            sa.String(64),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("target_enc", sa.LargeBinary, nullable=True),
        sa.Column("target_hmac", sa.LargeBinary(32), nullable=True),
        sa.Column("metadata_enc", sa.LargeBinary, nullable=True),
        sa.Column("prev_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("entry_hash", sa.LargeBinary(32), nullable=False),
    )
    op.create_index("ix_audit_log_actor_user_id", "audit_log", ["actor_user_id"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_target_hmac", "audit_log", ["target_hmac"])

    # Append-only triggers: reject every UPDATE / DELETE on audit_log.
    # Using BEFORE so the write never lands on disk; RAISE(ABORT, ...)
    # surfaces as a ``sqlite3.IntegrityError`` at the driver level.
    op.execute(
        """
        CREATE TRIGGER audit_log_no_update
        BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only');
        END;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_no_delete
        BEFORE DELETE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only');
        END;
        """
    )


def downgrade() -> None:
    """Reverse :func:`upgrade`.

    Order matters: drop triggers, drop tables in reverse dependency order
    (``audit_log`` / ``shares`` / ``vault_items`` before ``users``).
    """
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_delete;")
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update;")
    op.drop_index("ix_audit_log_target_hmac", table_name="audit_log")
    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_index("ix_audit_log_actor_user_id", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_index("ix_shares_recipient_user_id", table_name="shares")
    op.drop_index("ix_shares_sender_user_id", table_name="shares")
    op.drop_index("ix_shares_vault_item_id", table_name="shares")
    op.drop_table("shares")
    op.drop_index("ix_vault_items_filename_hmac", table_name="vault_items")
    op.drop_index("ix_vault_items_owner_user_id", table_name="vault_items")
    op.drop_table("vault_items")
    op.drop_index("ix_users_username_hmac", table_name="users")
    op.drop_table("users")
