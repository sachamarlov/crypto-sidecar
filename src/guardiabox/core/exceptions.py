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


# ---- Password validation ---------------------------------------------------


class WeakPasswordError(GuardiaBoxError):
    """The password fails the configured strength policy (zxcvbn score)."""
