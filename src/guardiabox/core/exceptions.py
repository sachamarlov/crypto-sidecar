"""Domain exceptions for the GuardiaBox core.

A flat hierarchy is preferred over deeply nested classes (KISS). Each exception
carries enough context for the UI layer to render a localised, actionable
message; exceptions never leak secrets in their string representation.
"""

from __future__ import annotations


class GuardiaBoxError(Exception):
    """Base class for all GuardiaBox domain errors."""


# ---- Container format ------------------------------------------------------


class InvalidContainerError(GuardiaBoxError):
    """The bytes do not represent a valid ``.crypt`` container."""


class UnsupportedVersionError(GuardiaBoxError):
    """The container version is newer than this build supports."""


class CorruptedContainerError(GuardiaBoxError):
    """The container layout is malformed (truncated, mis-sized fields, ...)."""


# ---- KDF -------------------------------------------------------------------


class UnknownKdfError(GuardiaBoxError):
    """The KDF identifier in the container is unknown to this build."""


class WeakKdfParametersError(GuardiaBoxError):
    """The KDF parameters fall below the project's minimum security baseline."""


# ---- Crypto ----------------------------------------------------------------


class DecryptionError(GuardiaBoxError):
    """Decryption failed — wrong password or tampered ciphertext.

    The two cases are intentionally indistinguishable to avoid timing oracles.
    """


class IntegrityError(GuardiaBoxError):
    """Authentication tag mismatch — the data has been altered."""


# ---- Path / I/O ------------------------------------------------------------


class PathTraversalError(GuardiaBoxError):
    """The provided path escapes the allowed root directory."""


class SymlinkEscapeError(GuardiaBoxError):
    """A symbolic link points outside the allowed root directory."""


class DestinationCollidesWithSourceError(GuardiaBoxError):
    """The destination path resolves to the same file as the source.

    Raised by encrypt/decrypt operations to prevent destructive
    in-place overwrites. On Linux, ``os.replace`` is silent about the
    collision — without this guard, ``decrypt_file(foo.crypt, dest=foo.crypt)``
    writes the plaintext over the ciphertext and loses it forever.
    """


class DestinationAlreadyExistsError(GuardiaBoxError):
    """The destination path points at an existing file.

    Raised by encrypt/decrypt when the caller did not explicitly request
    an overwrite (``force=False``). ``os.replace`` silently overwrites
    files on every platform; this guard surfaces the collision so users
    can opt in (``--force``) or pick a different destination.
    """


# ---- Password validation ---------------------------------------------------


class WeakPasswordError(GuardiaBoxError):
    """The password fails the configured strength policy (zxcvbn score)."""


# ---- Vault user (multi-user) -----------------------------------------------


class VaultUserNotFoundError(GuardiaBoxError):
    """A vault user lookup by name returned no row.

    Lives here (not in ``ui.cli._vault_audit``) so :func:`exit_for`
    can route it through the standard mapping without dragging the
    CLI helpers into a circular import with the audit hook.
    """


# ---- In-memory message bounds ----------------------------------------------


class MessageTooLargeError(GuardiaBoxError):
    """The plaintext / ciphertext message exceeds the in-memory limit.

    Raised by :func:`encrypt_message` / :func:`decrypt_message` when the
    payload would otherwise be loaded entirely into a ``bytearray``.
    Callers must route larger payloads through the file-based
    :func:`encrypt_file` / :func:`decrypt_file` API.
    """


# ---- Share token (spec 003) ------------------------------------------------


class ShareExpiredError(GuardiaBoxError):
    """The ``.gbox-share`` token's ``expires_at`` is in the past.

    Raised by :func:`accept_share` after the signature has verified, so
    a tampered token still surfaces as :class:`IntegrityError` first
    (anti-oracle ordering). Expiry is a legitimate, public-knowledge
    failure — distinguishing it from "wrong recipient" or "wrong sender
    pubkey" leaks no useful information to an attacker.
    """
