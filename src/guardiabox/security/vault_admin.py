"""Vault administrator key derivation.

The vault admin key is the single 32-byte AES-256 key used at the
repository boundary to encrypt / HMAC every sensitive DB column
(``username_enc``, ``filename_enc``, ``audit_log.target_enc``, ...).
It is derived from a vault administrator password via a KDF whose
salt + parameters live in a small JSON file alongside the SQLite DB.

File layout (inside ``Settings.data_dir``, typically ``~/.guardiabox/``)::

    vault.admin.json  — public config (salt, kdf_id, kdf_params hex)
    vault.db          — SQLCipher / SQLite file

The JSON file is **not** a secret: the salt and KDF parameters are
public inputs to the derivation. A reader still needs the password
to recompute the key.

Why separate from :mod:`guardiabox.security.keystore`?

The per-user keystore wraps two secrets (vault key, RSA private) under
a master key. The vault admin is simpler: no wrapped material, just
``KDF(password, salt, params) -> 32-byte key``. Sharing the keystore
module would either bloat its surface or force us to wrap a dummy
blob. A dedicated module keeps the contract narrow and testable.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import secrets
from typing import Any, Final

import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from guardiabox.core.constants import AES_GCM_NONCE_BYTES, AES_KEY_BYTES, SALT_BYTES
from guardiabox.core.exceptions import DecryptionError, GuardiaBoxError
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf, kdf_for_id
from guardiabox.security.password import assert_strong

__all__ = [
    "ADMIN_CONFIG_FILENAME",
    "VERIFICATION_AAD",
    "VERIFICATION_PAYLOAD",
    "VaultAdminConfig",
    "VaultAdminConfigAlreadyExistsError",
    "VaultAdminConfigInvalidError",
    "VaultAdminConfigMissingError",
    "create_admin_config",
    "derive_admin_key",
    "read_admin_config",
    "verify_admin_password",
    "write_admin_config",
]

#: AAD context for the verification blob -- binds the ciphertext to
#: this specific use, so a swap with another AES-GCM blob fails.
VERIFICATION_AAD: Final[bytes] = b"guardiabox/vault_admin/verification/v1"

#: Plaintext sealed under the admin key when the vault is initialised.
#: A successful decrypt of the verification_blob proves the supplied
#: password derives the right admin key (defeats the silent
#: "wrong-password = different-key" footgun).
VERIFICATION_PAYLOAD: Final[bytes] = b"GUARDIABOX_VAULT_OK"

#: Filename used inside the data dir. Plain JSON, no secret content.
ADMIN_CONFIG_FILENAME: Final[str] = "vault.admin.json"

#: Sidecar HMAC tag file. Audit C P0-3 / β-7: vault.admin.json itself
#: is integrity-only via its verification_blob (which proves "someone
#: knew a password capable of producing some key"). An attacker with
#: filesystem write access can substitute the whole file (with their
#: own salt + verification_blob) and DoS the legitimate user. The
#: HMAC tag, computed under a per-vault random secret stored in
#: ``vault.admin.json.hmac.key`` chmod 0600, makes the substitution
#: detectable. Trade-off documented in ADR-0020 (key-storage choice
#: -- random sibling secret instead of OS keychain because keychain
#: APIs differ per OS and the bundled binary cannot fan out without
#: pulling in keyring + win32crypt as runtime deps).
ADMIN_CONFIG_HMAC_FILENAME: Final[str] = "vault.admin.json.hmac"
ADMIN_CONFIG_HMAC_KEY_FILENAME: Final[str] = "vault.admin.json.hmac.key"
HMAC_KEY_BYTES: Final[int] = 32


class VaultAdminTamperError(GuardiaBoxError, ValueError):
    """The admin config HMAC does not match the sidecar tag file."""


class VaultAdminConfigMissingError(GuardiaBoxError):
    """The admin config file does not exist — run ``guardiabox init``."""


class VaultAdminConfigAlreadyExistsError(GuardiaBoxError):
    """Attempted to re-initialise an existing admin config."""


class VaultAdminConfigInvalidError(GuardiaBoxError, ValueError):
    """The admin config file exists but cannot be parsed / validated.

    Inherits :class:`ValueError` so existing ``pytest.raises(ValueError)``
    in tests still catches it; ``GuardiaBoxError`` lets the CLI
    ``exit_for`` mapping route it through the domain-error branch.
    """


@dataclass(frozen=True, slots=True)
class VaultAdminConfig:
    """Public parameters needed to re-derive the vault admin key.

    Field values are stable for the lifetime of the vault — rotating
    them is equivalent to re-keying every encrypted column and is
    tracked separately (post-MVP).

    ``verification_blob`` is an AES-GCM ciphertext (12-byte nonce ||
    ciphertext || 16-byte tag) of :data:`VERIFICATION_PAYLOAD` sealed
    under the admin key, with :data:`VERIFICATION_AAD` as associated
    data. A successful decrypt proves the supplied password derives
    the right key -- without it, a wrong password silently produces a
    *different* but still-32-byte key that only fails when used to
    decrypt a real database column. This eliminates that footgun and
    lets the unlock endpoint return a 401 immediately.
    """

    salt: bytes
    kdf_id: int
    kdf_params: bytes
    verification_blob: bytes

    # -- Serialisation ------------------------------------------------------

    def to_json(self) -> str:
        payload: dict[str, Any] = {
            "salt": self.salt.hex(),
            "kdf_id": self.kdf_id,
            "kdf_params": self.kdf_params.hex(),
            "verification_blob": self.verification_blob.hex(),
            "schema_version": 2,
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, blob: str) -> VaultAdminConfig:
        raw = json.loads(blob)
        if not isinstance(raw, dict):
            raise VaultAdminConfigInvalidError(
                f"admin config must be a JSON object, got {type(raw).__name__}"
            )
        if raw.get("schema_version") != 2:
            raise VaultAdminConfigInvalidError(
                f"admin config schema_version {raw.get('schema_version')!r} not supported "
                "(expected 2; pre-1.0 schema_version=1 vaults must be re-initialised)"
            )
        salt_hex = raw.get("salt")
        kdf_id = raw.get("kdf_id")
        kdf_params_hex = raw.get("kdf_params")
        verification_hex = raw.get("verification_blob")
        if (
            not isinstance(salt_hex, str)
            or not isinstance(kdf_params_hex, str)
            or not isinstance(verification_hex, str)
        ):
            raise VaultAdminConfigInvalidError(
                "admin config fields 'salt', 'kdf_params', 'verification_blob' must be hex strings"
            )
        if not isinstance(kdf_id, int):
            raise VaultAdminConfigInvalidError("admin config field 'kdf_id' must be an integer")
        salt = bytes.fromhex(salt_hex)
        if len(salt) != SALT_BYTES:
            raise VaultAdminConfigInvalidError(
                f"admin config salt must be {SALT_BYTES} bytes, got {len(salt)}"
            )
        return cls(
            salt=salt,
            kdf_id=kdf_id,
            kdf_params=bytes.fromhex(kdf_params_hex),
            verification_blob=bytes.fromhex(verification_hex),
        )


# ---------------------------------------------------------------------------
# Create / read / write
# ---------------------------------------------------------------------------


def create_admin_config(
    password: str,
    *,
    kdf: Pbkdf2Kdf | Argon2idKdf | None = None,
) -> VaultAdminConfig:
    """Validate ``password`` and return a fresh config with random salt.

    The returned object must be persisted with :func:`write_admin_config`
    before the caller discards it — there is no recovery from a lost
    salt + KDF params.

    Side-effect: derives the admin key in-process to seal the
    ``verification_blob``. The temporary key is zero-filled before
    return; the persisted blob carries no secret material in cleartext.
    """
    import unicodedata

    assert_strong(password)
    kdf_impl: Pbkdf2Kdf | Argon2idKdf = kdf if kdf is not None else Pbkdf2Kdf()
    salt = secrets.token_bytes(SALT_BYTES)

    # Derive the admin key once to seal the verification payload, then
    # zero-fill the buffer. The persisted blob is reproducible only by
    # the user who knows the password.
    password_bytes = unicodedata.normalize("NFC", password).encode("utf-8")
    transient = bytearray(kdf_impl.derive(password_bytes, salt, AES_KEY_BYTES))
    try:
        nonce = secrets.token_bytes(AES_GCM_NONCE_BYTES)
        ciphertext = AESGCM(bytes(transient)).encrypt(nonce, VERIFICATION_PAYLOAD, VERIFICATION_AAD)
        verification_blob = nonce + ciphertext
    finally:
        for i in range(len(transient)):
            transient[i] = 0

    return VaultAdminConfig(
        salt=salt,
        kdf_id=kdf_impl.kdf_id,
        kdf_params=kdf_impl.encode_params(),
        verification_blob=verification_blob,
    )


def derive_admin_key(config: VaultAdminConfig, password: str) -> bytes:
    """Return the 32-byte AES-256 vault admin key.

    NFC-normalisation and UTF-8 encoding match the encrypt/decrypt
    password path so visually-identical codepoint sequences derive
    the same key.

    Note: this function does **not** validate the password. Use
    :func:`verify_admin_password` when the caller needs to reject a
    wrong password before opening a vault session.
    """
    import unicodedata

    password_bytes = unicodedata.normalize("NFC", password).encode("utf-8")
    kdf = kdf_for_id(config.kdf_id, config.kdf_params)
    return kdf.derive(password_bytes, config.salt, AES_KEY_BYTES)


def verify_admin_password(config: VaultAdminConfig, password: str) -> bytes:
    """Derive the admin key and prove ``password`` is correct.

    Decrypts ``config.verification_blob`` with the derived key. If the
    AES-GCM tag matches, the password is the right one and the key is
    returned to the caller. If the tag does not match, the function
    raises :class:`DecryptionError` so the caller can route the
    failure to a uniform 401 / "unlock failed" response (anti-oracle).

    Args:
        config: The :class:`VaultAdminConfig` loaded from disk.
        password: The candidate admin password.

    Returns:
        The 32-byte admin key (immutable bytes). Caller is expected
        to copy into a bytearray + zero-fill when done.

    Raises:
        DecryptionError: ``password`` does not match the one that
            sealed ``config.verification_blob``.
    """
    # Audit C P2-2 / ε-34: candidate_key copied into a bytearray so
    # the SessionStore can zero-fill on close. The local immutable
    # bytes (returned by derive_admin_key) lives only the duration
    # of this function.
    candidate_key = bytearray(derive_admin_key(config, password))
    nonce = config.verification_blob[:AES_GCM_NONCE_BYTES]
    ciphertext = config.verification_blob[AES_GCM_NONCE_BYTES:]
    try:
        AESGCM(bytes(candidate_key)).decrypt(nonce, ciphertext, VERIFICATION_AAD)
    except InvalidTag as exc:
        # Zero-fill before propagating so the partially-derived key
        # disappears even on the failure path.
        for i in range(len(candidate_key)):
            candidate_key[i] = 0
        raise DecryptionError("admin password verification failed") from exc
    return bytes(candidate_key)


def write_admin_config(path: Path, config: VaultAdminConfig) -> None:
    """Persist ``config`` at ``path`` + HMAC tag. Refuses to overwrite an existing file.

    On POSIX we chmod 0600 after the write so only the owning user can
    read it. On Windows, ACL semantics differ and the chmod is a
    no-op; the user's home directory ACL already gates access.

    Audit β-7: write a sidecar HMAC tag (``vault.admin.json.hmac``)
    keyed by a per-vault random secret (``vault.admin.json.hmac.key``,
    chmod 0600). The pair makes substitution attacks detectable at
    read time -- an attacker would need both the JSON write and the
    HMAC key to forge a valid tag, raising the bar from "any
    filesystem write" to "filesystem write + secret read".
    """
    if path.exists():
        raise VaultAdminConfigAlreadyExistsError(
            f"admin config already exists at {path}; remove it to re-initialise"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    json_payload = config.to_json()
    path.write_text(json_payload, encoding="utf-8")
    _restrict_permissions(path)

    # Generate per-vault HMAC key + write the tag computed under it.
    hmac_key_path = path.with_name(ADMIN_CONFIG_HMAC_KEY_FILENAME)
    hmac_tag_path = path.with_name(ADMIN_CONFIG_HMAC_FILENAME)
    hmac_key = secrets.token_bytes(HMAC_KEY_BYTES)
    hmac_key_path.write_bytes(hmac_key)
    _restrict_permissions(hmac_key_path)
    tag = hmac.new(hmac_key, json_payload.encode("utf-8"), "sha256").digest()
    hmac_tag_path.write_bytes(tag)
    _restrict_permissions(hmac_tag_path)


def read_admin_config(path: Path) -> VaultAdminConfig:
    """Load and validate the admin config at ``path`` + verify HMAC tag.

    Audit β-7: refuses to load a vault.admin.json whose HMAC does not
    match the sidecar tag file. Migration: vaults predating the HMAC
    seal (no key file present) are upgraded transparently on first
    successful read by writing a fresh tag -- the security gain is
    only on subsequent reads, but that is the expected lifecycle.
    """
    if not path.is_file():
        raise VaultAdminConfigMissingError(
            f"admin config not found at {path}. Run `guardiabox init` to create one."
        )
    json_payload = path.read_text(encoding="utf-8")

    hmac_key_path = path.with_name(ADMIN_CONFIG_HMAC_KEY_FILENAME)
    hmac_tag_path = path.with_name(ADMIN_CONFIG_HMAC_FILENAME)
    if hmac_key_path.is_file() and hmac_tag_path.is_file():
        hmac_key = hmac_key_path.read_bytes()
        expected = hmac_tag_path.read_bytes()
        actual = hmac.new(hmac_key, json_payload.encode("utf-8"), "sha256").digest()
        if not hmac.compare_digest(actual, expected):
            raise VaultAdminTamperError(
                "vault.admin.json HMAC mismatch -- the file may have been tampered with. "
                "If you intentionally regenerated it, delete vault.admin.json.hmac and re-init."
            )
    else:
        # Legacy vault: no HMAC sidecar yet. Backfill on first read.
        new_key = secrets.token_bytes(HMAC_KEY_BYTES)
        new_tag = hmac.new(new_key, json_payload.encode("utf-8"), "sha256").digest()
        hmac_key_path.write_bytes(new_key)
        _restrict_permissions(hmac_key_path)
        hmac_tag_path.write_bytes(new_tag)
        _restrict_permissions(hmac_tag_path)

    return VaultAdminConfig.from_json(json_payload)


def _restrict_permissions(path: Path) -> None:
    """Chmod 0600 on POSIX; no-op on Windows."""
    if os.name == "posix":
        path.chmod(0o600)
