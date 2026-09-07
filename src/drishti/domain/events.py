from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SourceRef(BaseModel):
    """Stable identity of the system that emitted an event."""

    model_config = ConfigDict(frozen=True)

    tenant_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9._:-]+$")
    source_id: str = Field(min_length=1, max_length=256)
    source_type: str = Field(default="unknown", min_length=1, max_length=128)


class RawEvent(BaseModel):
    """Lossless evidence envelope used before parsing begins."""

    model_config = ConfigDict(frozen=True)

    event_id: UUID
    trace_id: UUID
    source: SourceRef
    received_at: datetime
    observed_at: datetime | None = None
    raw_bytes: bytes
    raw_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("received_at", "observed_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("timestamps must include a timezone")
        return value

    @classmethod
    def create(
        cls,
        *,
        event_id: UUID,
        trace_id: UUID,
        source: SourceRef,
        raw_bytes: bytes,
        idempotency_key: str | None,
        observed_at: datetime | None,
        received_at: datetime | None = None,
    ) -> RawEvent:
        received = received_at or datetime.now(UTC)
        return cls(
            event_id=event_id,
            trace_id=trace_id,
            source=source,
            received_at=received,
            observed_at=observed_at,
            raw_bytes=raw_bytes,
            raw_sha256=hashlib.sha256(raw_bytes).hexdigest(),
            idempotency_key=idempotency_key,
        )

    def verify_integrity(self) -> bool:
        """Recompute the digest to detect accidental or malicious mutation."""
        return hashlib.sha256(self.raw_bytes).hexdigest() == self.raw_sha256
