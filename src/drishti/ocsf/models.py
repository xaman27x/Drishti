from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class SchemaIdentity(BaseModel):
    model_config = ConfigDict(frozen=True)

    ocsf_version: str
    drishti_extension_version: str
    bundle_sha256: str


class ValidationIssue(BaseModel):
    model_config = ConfigDict(frozen=True)

    severity: Literal["error", "warning"] = "error"
    code: str
    path: str
    message: str


class ValidationReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    valid: bool
    schema_identity: SchemaIdentity = Field(serialization_alias="schema")
    class_name: str | None
    issues: tuple[ValidationIssue, ...]
    validated_event: dict[str, Any]
