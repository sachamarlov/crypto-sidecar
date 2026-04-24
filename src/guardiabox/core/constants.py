"""Cryptographic and format constants.

Single source of truth for every parameter that influences the on-disk format
or the security guarantees of the system. Changing any value here is a
**breaking change** that must be tracked in an ADR and accompanied by a new
container version byte.
"""

from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------
# Container format identification
# ---------------------------------------------------------------------------

CONTAINER_MAGIC: Final[bytes] = b"GBOX"
"""Magic bytes prefixing every ``.crypt`` file."""

CONTAINER_VERSION: Final[int] = 1
"""Current ``.crypt`` format version. Bump on any breaking layout change."""

# ---------------------------------------------------------------------------
# KDF identifiers (encoded as 1 byte in the container header)
# ---------------------------------------------------------------------------

KDF_ID_PBKDF2_SHA256: Final[int] = 0x01
KDF_ID_ARGON2ID: Final[int] = 0x02

# ---------------------------------------------------------------------------
# KDF parameter floors (enforced at encode / decode; weaker params are refused)
# ---------------------------------------------------------------------------

PBKDF2_MIN_ITERATIONS: Final[int] = 600_000
"""OWASP 2026 Password Storage CS — FIPS-140-compliant iteration floor."""

PBKDF2_MAX_ITERATIONS: Final[int] = 10_000_000
"""Upper cap on PBKDF2 iterations. A crafted ``.crypt`` with a huge
``uint32`` iteration count would otherwise lock a decoder for hours of
CPU before the tag check fails. 10 M iterations bound the worst case
to a few tens of seconds on a slow host — far beyond any legitimate
setting, well below the 4 billion ceiling of a ``uint32`` encoding."""

ARGON2_MIN_MEMORY_KIB: Final[int] = 64 * 1024
"""OWASP 2026 — minimum memory cost for Argon2id (64 MiB)."""

ARGON2_MAX_MEMORY_KIB: Final[int] = 1 * 1024 * 1024
"""Upper cap on Argon2id memory cost: 1 GiB. Prevents a crafted header
that requests 4 TiB (raw ``uint32`` max) from triggering an OOM or
multi-minute swap storm before authentication fails."""

ARGON2_MIN_TIME_COST: Final[int] = 3
"""OWASP 2026 — minimum time cost (iterations) for Argon2id."""

ARGON2_MAX_TIME_COST: Final[int] = 20
"""Upper cap on Argon2id time cost. Guards against a crafted parameter
blob that drags out authentication unreasonably."""

ARGON2_MIN_PARALLELISM: Final[int] = 1
"""OWASP 2026 — minimum parallelism for Argon2id."""

ARGON2_MAX_PARALLELISM: Final[int] = 16
"""Upper cap on Argon2id parallelism. Any reasonable host is covered;
higher values are rejected to bound thread creation on a crafted header."""

KDF_PARAMS_MAX_BYTES: Final[int] = 4096
"""Upper bound on the serialised KDF-params blob. Defence against DoS-sized
headers crafted by a malicious container."""

# ---------------------------------------------------------------------------
# Cipher parameters
# ---------------------------------------------------------------------------

AES_KEY_BYTES: Final[int] = 32  # AES-256
AES_GCM_NONCE_BYTES: Final[int] = 12  # NIST SP 800-38D recommended
AES_GCM_TAG_BYTES: Final[int] = 16

SALT_BYTES: Final[int] = 16
"""NIST SP 800-132 §5.1 — random salt of at least 128 bits."""

# ---------------------------------------------------------------------------
# Default streaming parameters
# ---------------------------------------------------------------------------

DEFAULT_CHUNK_BYTES: Final[int] = 64 * 1024
"""Default chunk size for streaming encryption / decryption."""

# ---------------------------------------------------------------------------
# File extensions
# ---------------------------------------------------------------------------

ENCRYPTED_SUFFIX: Final[str] = ".crypt"
DECRYPTED_SUFFIX: Final[str] = ".decrypt"
SHARE_TOKEN_SUFFIX: Final[str] = ".gbox-share"  # noqa: S105 — file extension, not a credential value
