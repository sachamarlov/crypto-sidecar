"""Shared Pydantic v2 base classes for the sidecar API (ADR-0016 §H).

Every request / response body inherits :class:`SidecarBaseModel`, which
forbids extra fields and freezes the instance so a downstream caller
cannot mutate a parsed payload mid-flight. Password fields use
:class:`pydantic.SecretStr` so ``model.model_dump()`` and
``repr(model)`` redact the value automatically -- defensive layer on
top of the project-wide ``_redact_secrets`` structlog processor.

Per-router schemas (encrypt request, decrypt response, ...) live in
their respective router modules to keep the imports tight; this
module owns only the cross-cutting types.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

__all__ = [
    "ErrorResponse",
    "SidecarBaseModel",
]


class SidecarBaseModel(BaseModel):
    """Base for every request / response body served by the sidecar.

    * ``strict=True`` -- a ``str`` does not become an ``int`` silently.
    * ``extra="forbid"`` -- unknown fields are a programming error
      (the frontend client is auto-generated from the OpenAPI schema;
      drift between client and server should fail at deserialise time,
      not at runtime).
    * ``frozen=True`` -- the model is hashable and immutable; safer
      shape for the in-process passing through dependency-injection.
    """

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
    )


class ErrorResponse(SidecarBaseModel):
    """Uniform error body returned by every routed exception handler.

    The single ``detail`` string carries the user-facing message --
    deliberately constant per failure class to preserve ADR-0016 §C
    anti-oracle propagation. Specifically: post-KDF decrypt failures
    must collapse to a single string regardless of whether the cause
    was a wrong password or a tampered ciphertext.
    """

    detail: str
