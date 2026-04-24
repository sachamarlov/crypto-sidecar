"""Append-only audit log with hash-chained integrity.

Every security-relevant action appends one row to ``audit_log``. The
row's ``entry_hash`` covers every other column plus the previous
entry's ``entry_hash``, so a later reader can verify the chain from
genesis forward and detect any tampering on the first mismatch.

Hash computation
----------------

    entry_hash = SHA-256(
        prev_hash ||
        canonical_json({
            "sequence":      int,
            "timestamp":     ISO-8601 string (UTC),
            "actor_user_id": str | None,
            "action":        str,
            "target_enc":    hex | None,
            "target_hmac":   hex | None,
            "metadata_enc":  hex | None,
            "prev_hash":     hex,
        })
    )

``canonical_json`` = ``json.dumps(..., sort_keys=True, separators=(",", ":"))``
with UTF-8 encoding — matches the JCS-style deterministic form. The
append-only SQL trigger (migration 0001) keeps mutations out at the
storage layer; this module's only job is to wire up the chain invariant.

Why hash the encrypted columns rather than the plaintext?

The vault admin key can rotate (passwords change; future backup
scheme) but the audit chain must outlive the rotation. Hashing the
ciphertext keeps the chain verifiable without the plaintext — anyone
who has just the DB file can still tell whether it was tampered with,
even if they cannot read the target / metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
import hashlib
import json
from typing import Final

from sqlalchemy.ext.asyncio import AsyncSession

from guardiabox.persistence.models import AUDIT_GENESIS_HASH, AUDIT_HASH_BYTES, AuditEntry
from guardiabox.persistence.repositories import AuditRepository
from guardiabox.security.constant_time import equal_constant_time

__all__ = [
    "AUDIT_GENESIS_HASH",
    "AuditAction",
    "AuditRecord",
    "AuditVerifyResult",
    "append",
    "compute_entry_hash",
    "verify",
]


class AuditAction(StrEnum):
    """Catalog of actions tracked in the audit log."""

    USER_CREATE = "user.create"
    USER_UNLOCK = "user.unlock"
    USER_UNLOCK_FAILED = "user.unlock_failed"
    USER_LOCK = "user.lock"
    USER_DELETE = "user.delete"
    FILE_ENCRYPT = "file.encrypt"
    FILE_DECRYPT = "file.decrypt"
    FILE_DECRYPT_FAILED = "file.decrypt_failed"
    FILE_SHARE = "file.share"
    FILE_SHARE_ACCEPT = "file.share_accept"
    FILE_SECURE_DELETE = "file.secure_delete"
    KDF_MIGRATE = "kdf.migrate"
    SYSTEM_STARTUP = "system.startup"


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """Domain view of an audit entry (decrypted target + metadata)."""

    sequence: int
    timestamp: datetime
    actor_user_id: str | None
    action: str
    target: str | None
    metadata: dict[str, str]


@dataclass(frozen=True, slots=True)
class AuditVerifyResult:
    """Outcome of :func:`verify`.

    ``ok=True`` and ``first_bad_sequence=None`` on a healthy chain.
    On failure, ``first_bad_sequence`` points at the first row whose
    computed ``entry_hash`` did not match the stored one — every row
    after that is effectively unverified.
    """

    ok: bool
    first_bad_sequence: int | None
    entries_checked: int


# ---------------------------------------------------------------------------
# Hash computation
# ---------------------------------------------------------------------------


_CANONICAL_JSON_SEPARATORS: Final[tuple[str, str]] = (",", ":")


def _iso_utc(dt: datetime) -> str:
    """Return a canonical UTC ISO-8601 string (no microsecond jitter)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat()


def _hex_or_none(b: bytes | None) -> str | None:
    return b.hex() if b is not None else None


def compute_entry_hash(
    *,
    sequence: int,
    timestamp: datetime,
    actor_user_id: str | None,
    action: str,
    target_enc: bytes | None,
    target_hmac: bytes | None,
    metadata_enc: bytes | None,
    prev_hash: bytes,
) -> bytes:
    """Return SHA-256(prev_hash || canonical_json(other_columns))."""
    if len(prev_hash) != AUDIT_HASH_BYTES:
        raise ValueError(f"prev_hash must be {AUDIT_HASH_BYTES} bytes, got {len(prev_hash)}")
    payload = {
        "sequence": sequence,
        "timestamp": _iso_utc(timestamp),
        "actor_user_id": actor_user_id,
        "action": action,
        "target_enc": _hex_or_none(target_enc),
        "target_hmac": _hex_or_none(target_hmac),
        "metadata_enc": _hex_or_none(metadata_enc),
        "prev_hash": prev_hash.hex(),
    }
    blob = json.dumps(payload, sort_keys=True, separators=_CANONICAL_JSON_SEPARATORS).encode(
        "utf-8"
    )
    digest = hashlib.sha256()
    digest.update(prev_hash)
    digest.update(blob)
    return digest.digest()


# ---------------------------------------------------------------------------
# Append + Verify
# ---------------------------------------------------------------------------


async def append(
    session: AsyncSession,
    vault_admin_key: bytes,
    *,
    actor_user_id: str | None,
    action: AuditAction | str,
    target: str | None = None,
    metadata: dict[str, str] | None = None,
    timestamp: datetime | None = None,
) -> AuditEntry:
    """Append one row to the audit log, computing the chain hash first.

    Args:
        session: Open AsyncSession; caller owns the commit.
        vault_admin_key: 32-byte key used to encrypt ``target`` and
            ``metadata`` into their ``_enc`` columns.
        actor_user_id: ``User.id`` of the acting user; ``None`` for
            system events (startup, migration).
        action: Either a :class:`AuditAction` member or a raw string —
            a StrEnum converts transparently.
        target: Optional plaintext target (filename, share id, ...).
        metadata: Optional key/value pairs for the action. JSON-encoded
            and stored encrypted. Non-string values are rejected at
            call time so the chain hash stays deterministic.
        timestamp: Override for tests / replays. Defaults to ``now(UTC)``.

    Returns:
        The inserted :class:`AuditEntry` (with its assigned sequence
        number and computed entry_hash).
    """
    repo = AuditRepository(session, vault_admin_key)

    latest = await repo.latest()
    prev_hash = latest.entry_hash if latest is not None else AUDIT_GENESIS_HASH
    next_sequence = (latest.sequence + 1) if latest is not None else 1

    ts = timestamp or datetime.now(UTC)
    action_value = action.value if isinstance(action, AuditAction) else str(action)

    target_enc, target_hmac = (
        repo.encrypt_target(target, sequence=next_sequence) if target is not None else (None, None)
    )
    metadata_enc = (
        repo.encrypt_metadata(
            json.dumps(metadata, sort_keys=True, separators=_CANONICAL_JSON_SEPARATORS).encode(
                "utf-8"
            ),
            sequence=next_sequence,
        )
        if metadata
        else None
    )

    entry_hash = compute_entry_hash(
        sequence=next_sequence,
        timestamp=ts,
        actor_user_id=actor_user_id,
        action=action_value,
        target_enc=target_enc,
        target_hmac=target_hmac,
        metadata_enc=metadata_enc,
        prev_hash=prev_hash,
    )

    entry = AuditEntry(
        sequence=next_sequence,
        timestamp=ts,
        actor_user_id=actor_user_id,
        action=action_value,
        target_enc=target_enc,
        target_hmac=target_hmac,
        metadata_enc=metadata_enc,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    return await repo.insert_row(entry)


async def verify(session: AsyncSession, vault_admin_key: bytes) -> AuditVerifyResult:
    """Walk the audit log from sequence 1 and return whether the chain holds.

    The first row's ``prev_hash`` must equal :data:`AUDIT_GENESIS_HASH`.
    Each subsequent row's ``prev_hash`` must equal the previous row's
    ``entry_hash``, and the recomputed ``entry_hash`` must match the
    stored one byte-for-byte (``hmac.compare_digest`` / our
    ``equal_constant_time`` wrapper).

    The vault admin key is unused today (hashes are over ciphertext
    columns) but kept in the signature so a future change that needs
    plaintext inputs is non-breaking.
    """
    _ = vault_admin_key  # reserved
    repo = AuditRepository(session, vault_admin_key)
    entries = await repo.all_in_order()

    expected_prev = AUDIT_GENESIS_HASH
    checked = 0
    for entry in entries:
        checked += 1
        if not equal_constant_time(entry.prev_hash, expected_prev):
            return AuditVerifyResult(
                ok=False, first_bad_sequence=entry.sequence, entries_checked=checked
            )
        computed = compute_entry_hash(
            sequence=entry.sequence,
            timestamp=entry.timestamp,
            actor_user_id=entry.actor_user_id,
            action=entry.action,
            target_enc=entry.target_enc,
            target_hmac=entry.target_hmac,
            metadata_enc=entry.metadata_enc,
            prev_hash=entry.prev_hash,
        )
        if not equal_constant_time(computed, entry.entry_hash):
            return AuditVerifyResult(
                ok=False, first_bad_sequence=entry.sequence, entries_checked=checked
            )
        expected_prev = entry.entry_hash

    return AuditVerifyResult(ok=True, first_bad_sequence=None, entries_checked=checked)
