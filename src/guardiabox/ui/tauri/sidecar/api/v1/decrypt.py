r"""POST /api/v1/decrypt -- delegates to :func:`core.operations.decrypt_file`.

Anti-oracle (ADR-0015 propagated to HTTP per ADR-0016 sec C):
:class:`DecryptionError` and :class:`IntegrityError` -- the two
post-KDF failure modes -- both collapse to a single
``HTTPException(422, detail="decryption failed")``. The frontend
cannot tell wrong-password from tampered-ciphertext, exactly like
the CLI / TUI cannot at their layer.

Pre-KDF failures (invalid container header, unsupported version,
unknown KDF, weak KDF parameters) keep their distinct 4xx codes
because their existence is a function of public-only metadata.
"""

from __future__ import annotations

from pathlib import Path
import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import Field, SecretStr

from guardiabox.config import Settings
from guardiabox.core.exceptions import (
    CorruptedContainerError,
    DecryptionError,
    DestinationAlreadyExistsError,
    DestinationCollidesWithSourceError,
    IntegrityError,
    InvalidContainerError,
    PathTraversalError,
    SymlinkEscapeError,
    UnknownKdfError,
    UnsupportedVersionError,
    WeakKdfParametersError,
)
from guardiabox.core.operations import decrypt_file
from guardiabox.logging import get_logger
from guardiabox.ui.tauri.sidecar.api.rate_limit import BUCKET_WRITE, limiter
from guardiabox.ui.tauri.sidecar.api.schemas import SidecarBaseModel

__all__ = ["build_decrypt_router"]

_log = get_logger("guardiabox.sidecar.decrypt")

#: Constant detail string returned for every post-KDF decrypt
#: failure. ADR-0016 sec C: missing/wrong password and tampered
#: ciphertext must be byte-identical at the wire.
ANTI_ORACLE_DETAIL = "decryption failed"


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class DecryptRequest(SidecarBaseModel):
    """Body of ``POST /api/v1/decrypt``."""

    path: str = Field(description="Absolute filesystem path of the .crypt file.")
    password: SecretStr
    dest: str | None = Field(
        default=None,
        description="Optional output path; defaults to <source>.decrypt alongside the source.",
    )
    force: bool = False


class DecryptResponse(SidecarBaseModel):
    """Body of a successful ``POST /api/v1/decrypt``."""

    output_path: str
    plaintext_size: int
    ciphertext_size: int
    kdf_id: int
    elapsed_ms: int


# ---------------------------------------------------------------------------
# Dependency injection
# ---------------------------------------------------------------------------


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def build_decrypt_router() -> APIRouter:
    """Return the ``/api/v1/decrypt`` router."""
    router = APIRouter(prefix="/api/v1", tags=["decrypt"])

    @router.post(
        "/decrypt",
        response_model=DecryptResponse,
        status_code=status.HTTP_200_OK,
    )
    @limiter.limit(BUCKET_WRITE)
    def decrypt(
        request: Request,
        body: DecryptRequest,
        settings: Annotated[Settings, Depends(_settings)],
    ) -> DecryptResponse:
        del request  # consumed by slowapi via signature inspection
        # Audit C P1-2: see encrypt.py for rationale; same allow-list
        # (vault data_dir + user home) applied here.
        source = Path(body.path)
        dest_path = Path(body.dest) if body.dest is not None else None
        allowed_root = _resolve_allowed_root(source, settings)
        if allowed_root is None:
            raise HTTPException(status_code=400, detail="path validation failed")

        if not source.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"source file not found: {source}",
            )

        start = time.monotonic()
        try:
            output = decrypt_file(
                source,
                body.password.get_secret_value(),
                root=allowed_root,
                dest=dest_path,
                force=body.force,
            )
        # Pre-KDF failures: distinct codes (their causes are public metadata).
        except (InvalidContainerError, UnsupportedVersionError, UnknownKdfError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except (CorruptedContainerError, WeakKdfParametersError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except (PathTraversalError, SymlinkEscapeError) as exc:
            raise HTTPException(status_code=400, detail="path validation failed") from exc
        except (DestinationCollidesWithSourceError, DestinationAlreadyExistsError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        # Post-KDF failures: anti-oracle (single constant body).
        except (DecryptionError, IntegrityError) as exc:
            # IMPORTANT: the structlog event below intentionally does
            # NOT carry the exception type. Logging "DecryptionError
            # vs IntegrityError" on stderr would re-introduce the
            # exact oracle ADR-0015 closes -- the discriminator must
            # not appear anywhere observable by the attacker.
            _log.info("sidecar.decrypt.anti_oracle_failure")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=ANTI_ORACLE_DETAIL,
            ) from exc

        elapsed_ms = int((time.monotonic() - start) * 1000)
        ciphertext_size = source.stat().st_size
        plaintext_size = output.stat().st_size
        _log.info(
            "sidecar.decrypt.ok",
            ciphertext_size=ciphertext_size,
            plaintext_size=plaintext_size,
            elapsed_ms=elapsed_ms,
        )
        # kdf_id reading: read the header once for the response. The
        # core API does not currently surface kdf_id from decrypt_file;
        # we re-read the leading byte sequence rather than re-parse the
        # full container, since the body has already been validated.
        return DecryptResponse(
            output_path=str(output),
            plaintext_size=plaintext_size,
            ciphertext_size=ciphertext_size,
            kdf_id=_read_kdf_id_from_header(source),
            elapsed_ms=elapsed_ms,
        )

    return router


def _resolve_allowed_root(source: Path, settings: Settings) -> Path | None:
    """Return the first allowed ancestor of ``source``, or None on rejection.

    Audit C P1-2 mitigation: shared allow-list policy with encrypt.py
    (vault data_dir + user home). Refer to that module's helper for
    the full rationale.
    """
    try:
        resolved_source = source.resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    for root in (settings.data_dir.resolve(), Path.home().resolve()):
        try:
            resolved_source.relative_to(root)
        except ValueError:
            continue
        else:
            return root
    return None


def _read_kdf_id_from_header(crypt_path: Path) -> int:
    """Re-read the kdf_id byte from a ``.crypt`` header for response metadata."""
    # Container layout (ADR-0013): 4 bytes magic, 1 byte version,
    # 1 byte kdf_id, ...
    with crypt_path.open("rb") as fh:
        header = fh.read(6)
    if len(header) < 6:
        return 0
    return int(header[5])
