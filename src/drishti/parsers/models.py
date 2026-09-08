from __future__ import annotations

import base64
import hashlib
import json
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ParserFormat(StrEnum):
    RFC5424 = "rfc5424"
    CEF = "cef"


class Transform(StrEnum):
    IDENTITY = "identity"
    INTEGER = "integer"
    IP_ADDRESS = "ip_address"
    LOWERCASE = "lowercase"
    RFC3339_TO_EPOCH_MS = "rfc3339_to_epoch_ms"
    CEF_SEVERITY_TO_OCSF = "cef_severity_to_ocsf"
    SYSLOG_PRI_TO_OCSF_SEVERITY = "syslog_pri_to_ocsf_severity"


JsonScalar = str | int | float | bool


class FieldRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    target_path: str = Field(pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
    source_capture: str | None = Field(default=None, min_length=1)
    constant: JsonScalar | None = None
    transform: Transform = Transform.IDENTITY
    required: bool = False

    @model_validator(mode="after")
    def require_one_source(self) -> Self:
        if (self.source_capture is None) == (self.constant is None):
            raise ValueError("exactly one of source_capture or constant is required")
        if self.constant is not None and self.transform is not Transform.IDENTITY:
            raise ValueError("constant rules cannot apply transformations")
        return self


class ParserFixture(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1, max_length=128)
    raw_base64: str = Field(min_length=1)
    expected_fields: dict[str, Any]

    def raw_bytes(self) -> bytes:
        return base64.b64decode(self.raw_base64, validate=True)


class ResourceBudget(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_event_bytes: int = Field(default=65_536, ge=256, le=16_777_216)
    max_p95_parse_ms: float = Field(default=10.0, gt=0, le=1_000)
    max_rules: int = Field(default=128, ge=1, le=1_024)


class SourceDefinitionPack(BaseModel):
    """Declarative parser configuration; it contains no executable code."""

    model_config = ConfigDict(frozen=True)

    spec_version: str = "drishti.sdp/v1"
    pack_uid: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    version: str = Field(pattern=r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
    source_key: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    display_name: str = Field(min_length=1, max_length=256)
    parser_format: ParserFormat
    ocsf_version: str = "1.9.0"
    target_class_uid: int = Field(gt=0)
    rules: tuple[FieldRule, ...]
    fixtures: tuple[ParserFixture, ...]
    budget: ResourceBudget = ResourceBudget()
    generated_by: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_pack(self) -> Self:
        if not self.rules:
            raise ValueError("at least one field rule is required")
        if not self.fixtures:
            raise ValueError("at least one qualification fixture is required")
        if len(self.rules) > self.budget.max_rules:
            raise ValueError("field rule count exceeds the declared resource budget")
        targets = [rule.target_path for rule in self.rules]
        if len(targets) != len(set(targets)):
            raise ValueError("field rule targets must be unique")
        captures = [rule.source_capture for rule in self.rules if rule.source_capture is not None]
        if len(captures) != len(set(captures)):
            raise ValueError("a source capture may map to only one target field")
        return self

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def semver(self) -> tuple[int, int, int]:
        major, minor, patch = self.version.split(".")
        return int(major), int(minor), int(patch)
