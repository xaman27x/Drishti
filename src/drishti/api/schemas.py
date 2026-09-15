from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from drishti.domain.events import SourceRef
from drishti.ocsf.models import ValidationReport


class IngestEventRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9._:-]+$")
    source_id: str = Field(min_length=1, max_length=256)
    source_type: str = Field(default="unknown", min_length=1, max_length=128)
    payload_base64: str = Field(min_length=1)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=256)
    observed_at: datetime | None = None

    def source(self) -> SourceRef:
        return SourceRef(
            tenant_id=self.tenant_id,
            source_id=self.source_id,
            source_type=self.source_type,
        )

    def decode_payload(self) -> bytes:
        try:
            return base64.b64decode(self.payload_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("payload_base64 must contain valid canonical base64") from exc


class IngestEventResponse(BaseModel):
    event_id: UUID
    trace_id: UUID
    raw_sha256: str
    status: str = "archived"
    duplicate: bool


class ErrorResponse(BaseModel):
    detail: str


class ValidateOcsfRequest(BaseModel):
    event: dict[str, Any]


class ValidateOcsfResponse(ValidationReport):
    pass
