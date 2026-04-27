"""In-memory session store for the sidecar (ADR-0016 sec B).

The store maps a random ``session_id`` (32 octets URL-safe) to the
deri-vault material the routers need to talk to the persistence layer:

* ``admin_key`` -- the 32-octet AES-256 key derived from the vault
  administrator password (cf. :mod:`guardiabox.security.vault_admin`).
  Required by every repository call that reads / writes encrypted
  columns.
* ``user_unlocks`` -- per-user vault keys unwrapped from each user's
  Keystore. Required when an operation acts *as* a specific user
  (``--vault-user`` audit hook on encrypt / decrypt, share / accept).
  Empty until ``POST /api/v1/users/{id}/unlock`` is called for a
  given user (lands in G-06).

Lifecycle:

* TTL = ``auto_lock_minutes`` (cf. :class:`guardiabox.config.Settings`).
  Implemented as a check-on-access expiry rather than an asyncio
  reaper, so a freshly-spawned sidecar with no active session uses
  zero CPU. A periodic reaper is a follow-up improvement (out of MVP
  scope; documented as a TODO in the source).
* Closing a session zero-fills every ``bytearray`` it holds before
  dropping the dict entry. Python's bytes copies (the ones returned
  by ``kdf.derive``) outlive zero-fill; cf. THREAT_MODEL section 4.5.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import secrets
import time

from guardiabox.logging import get_logger

__all__ = [
    "SESSION_ID_BYTES",
    "SessionStore",
    "VaultSession",
]

#: URL-safe random bytes that produce a session id of ~43 chars.
SESSION_ID_BYTES = 32

_log = get_logger("guardiabox.sidecar.state")


@dataclass(slots=True)
class VaultSession:
    """One unlocked admin context, optionally with per-user vault keys."""

    session_id: str
    admin_key: bytearray
    expires_at: float
    user_unlocks: dict[str, bytearray] = field(default_factory=dict)


def _zero_fill(buf: bytearray) -> None:
    """Constant-cost wipe of a mutable buffer."""
    for i in range(len(buf)):
        buf[i] = 0


class SessionStore:
    """Thread-unsafe in-memory map of active vault sessions.

    The sidecar runs uvicorn in a single asyncio loop; the store is
    accessed sequentially from request handlers. If a future refactor
    moves the store across threads, wrap the inner dict with a
    :class:`threading.RLock` -- the call sites are tagged with
    ``ctx.acquire`` comments to make that drop-in cheap.
    """

    def __init__(self, *, ttl_seconds: float, clock: object = None) -> None:
        if ttl_seconds <= 0:
            msg = "ttl_seconds must be positive"
            raise ValueError(msg)
        self._ttl = float(ttl_seconds)
        self._sessions: dict[str, VaultSession] = {}
        # ``clock`` lets tests inject a deterministic monotonic source.
        # Default is the kernel's :func:`time.monotonic`.
        self._clock = clock if clock is not None else time.monotonic

    def _now(self) -> float:
        result: float = self._clock()  # type: ignore[operator]
        return result

    # -- Admin sessions ---------------------------------------------------

    def open_admin_session(self, admin_key: bytes) -> VaultSession:
        """Open a fresh session with ``admin_key`` and return its handle.

        Args:
            admin_key: The 32-octet vault administrator key. Caller is
                responsible for zero-filling its own buffer; this store
                copies the bytes into a fresh ``bytearray`` it owns.

        Returns:
            The freshly-minted :class:`VaultSession`. The caller stores
            its ``session_id`` and forwards it to subsequent requests.
        """
        if not admin_key:
            msg = "admin_key must not be empty"
            raise ValueError(msg)
        session_id = secrets.token_urlsafe(SESSION_ID_BYTES)
        session = VaultSession(
            session_id=session_id,
            admin_key=bytearray(admin_key),
            expires_at=self._now() + self._ttl,
        )
        self._sessions[session_id] = session
        _log.info("vault.session.opened", ttl_seconds=int(self._ttl))
        return session

    def get(self, session_id: str) -> VaultSession | None:
        """Return the session, refreshing its expiry; ``None`` if expired/absent.

        Each successful :meth:`get` slides the expiry forward by
        ``ttl_seconds`` -- a touched session never auto-locks
        unexpectedly while the user is actively working. An idle
        session expires exactly ``ttl_seconds`` after the last hit.
        """
        session = self._sessions.get(session_id)
        if session is None:
            return None
        if self._now() > session.expires_at:
            self._zero_fill_and_drop(session_id)
            _log.info("vault.session.expired")
            return None
        # Sliding expiry on access.
        session.expires_at = self._now() + self._ttl
        return session

    def close(self, session_id: str) -> bool:
        """Drop the session and zero-fill its buffers. Returns whether it existed."""
        if session_id not in self._sessions:
            return False
        self._zero_fill_and_drop(session_id)
        _log.info("vault.session.closed")
        return True

    # -- Per-user unlocks (consumed by G-06) ------------------------------

    def unlock_user(self, session_id: str, user_id: str, vault_key: bytes) -> None:
        """Attach ``vault_key`` to the session under ``user_id``.

        Raises:
            KeyError: The session does not exist or has expired.
        """
        session = self.get(session_id)
        if session is None:
            msg = "session not found or expired"
            raise KeyError(msg)
        # Replace any prior unlock for the same user, zero-filling the
        # outgoing buffer first so it never lingers.
        previous = session.user_unlocks.get(user_id)
        if previous is not None:
            _zero_fill(previous)
        session.user_unlocks[user_id] = bytearray(vault_key)

    def lock_user(self, session_id: str, user_id: str) -> bool:
        """Drop the per-user vault key. Returns whether anything changed."""
        session = self.get(session_id)
        if session is None:
            return False
        existing = session.user_unlocks.pop(user_id, None)
        if existing is None:
            return False
        _zero_fill(existing)
        return True

    # -- Maintenance ------------------------------------------------------

    def reap_expired(self) -> int:
        """Walk all sessions, drop expired ones, return the count reaped."""
        now = self._now()
        expired_ids = [sid for sid, session in self._sessions.items() if now > session.expires_at]
        for sid in expired_ids:
            self._zero_fill_and_drop(sid)
        if expired_ids:
            _log.info("vault.session.reaped", count=len(expired_ids))
        return len(expired_ids)

    def close_all(self) -> int:
        """Tear down every session (lifespan shutdown hook). Returns count."""
        count = len(self._sessions)
        for sid in list(self._sessions.keys()):
            self._zero_fill_and_drop(sid)
        return count

    def __len__(self) -> int:
        return len(self._sessions)

    # -- Internal --------------------------------------------------------

    def _zero_fill_and_drop(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return
        _zero_fill(session.admin_key)
        for buf in session.user_unlocks.values():
            _zero_fill(buf)
        session.user_unlocks.clear()
