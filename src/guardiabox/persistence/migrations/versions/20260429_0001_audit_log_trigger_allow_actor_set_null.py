"""Amend audit_log_no_update trigger to tolerate actor_user_id SET NULL cascade.

Revision ID: 20260429_0001
Revises: 20260424_0001
Create Date: 2026-04-29

Audit A P0-4: enabling ``PRAGMA foreign_keys = ON`` (engine event
listener in :mod:`guardiabox.persistence.database`) makes the
``ON DELETE SET NULL`` cascade on ``audit_log.actor_user_id`` fire
when a user is deleted. The original ``audit_log_no_update`` trigger
aborts every UPDATE unconditionally, which would block the cascade
and rollback the user delete.

This migration replaces the trigger with a conditional WHEN clause
that lets the cascade rewrite ``actor_user_id`` to NULL while still
rejecting every other column change. The ``NEW.actor_user_id IS NOT
NULL`` guard means:

* Cascade SET NULL: NEW.actor_user_id IS NULL -> WHEN false -> trigger
  does not fire -> UPDATE allowed.
* Manual reassignment to another user: NEW.actor_user_id IS NOT NULL
  -> trigger fires -> ABORT.

Forensic invariant preserved: orphan references are accepted (audit
log keeps a NULL actor when the user row is gone), other immutable
columns (sequence, timestamp, action, target_enc, target_hmac,
metadata_enc, prev_hash, entry_hash) all stay locked.
"""

from __future__ import annotations

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Replace ``audit_log_no_update`` trigger with the conditional WHEN clause."""
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update;")
    op.execute(
        """
        CREATE TRIGGER audit_log_no_update
        BEFORE UPDATE ON audit_log
        WHEN
            OLD.sequence != NEW.sequence
            OR OLD.timestamp != NEW.timestamp
            OR OLD.action != NEW.action
            OR OLD.target_enc IS NOT NEW.target_enc
            OR OLD.target_hmac IS NOT NEW.target_hmac
            OR OLD.metadata_enc IS NOT NEW.metadata_enc
            OR OLD.prev_hash != NEW.prev_hash
            OR OLD.entry_hash != NEW.entry_hash
            OR NEW.actor_user_id IS NOT NULL
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only');
        END;
        """
    )


def downgrade() -> None:
    """Restore the original unconditional ``audit_log_no_update`` trigger."""
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update;")
    op.execute(
        """
        CREATE TRIGGER audit_log_no_update
        BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only');
        END;
        """
    )
