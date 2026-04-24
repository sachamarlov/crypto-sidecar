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


# ---- In-memory message bounds ----------------------------------------------


class MessageTooLargeError(GuardiaBoxError):
    """The plaintext / ciphertext message exceeds the in-memory limit.

    Raised by :func:`encrypt_message` / :func:`decrypt_message` when the
    payload would otherwise be loaded entirely into a ``bytearray``.
    Callers must route larger payloads through the file-based
    :func:`encrypt_file` / :func:`decrypt_file` API.
    """
