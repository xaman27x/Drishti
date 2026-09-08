from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from drishti.domain.events import RawEvent
from drishti.ocsf.models import SchemaIdentity


class ByteDisposition(StrEnum):
    MAPPED = "mapped"
    STRUCTURAL = "structural"
    IGNORED = "ignored"
    UNMAPPED = "unmapped"


class ParserIdentity(BaseModel):
    model_config = ConfigDict(frozen=True)

    bundle_uid: str = Field(min_length=1)
    bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ByteClaim(BaseModel):
    model_config = ConfigDict(frozen=True)

    start: int = Field(ge=0)
    end: int = Field(gt=0)
    disposition: ByteDisposition
    fragment_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    rule_uid: str = Field(min_length=1)
    target_path: str | None = None
    transformation: str | None = None

    @model_validator(mode="after")
    def validate_span(self) -> Self:
        if self.end <= self.start:
            raise ValueError("end must be greater than start")
        if self.disposition is ByteDisposition.MAPPED and not self.target_path:
            raise ValueError("mapped claims require target_path")
        return self

    @classmethod
    def from_raw(
        cls,
        raw: bytes,
        *,
        start: int,
        end: int,
        disposition: ByteDisposition,
        rule_uid: str,
        target_path: str | None = None,
        transformation: str | None = None,
    ) -> ByteClaim:
        if start < 0 or end > len(raw) or end <= start:
            raise ValueError("claim span is outside the raw event")
        return cls(
            start=start,
            end=end,
            disposition=disposition,
            fragment_sha256=hashlib.sha256(raw[start:end]).hexdigest(),
            rule_uid=rule_uid,
            target_path=target_path,
            transformation=transformation,
        )


class ConservationCertificate(BaseModel):
    model_config = ConfigDict(frozen=True)

    raw_event_id: UUID
    raw_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    total_bytes: int = Field(ge=0)
    accounted_bytes: int = Field(ge=0)
    conservation_score: float = Field(ge=0, le=1)
    fully_accounted: bool
    normalization_revision: int = Field(ge=1)
    schema_identity: SchemaIdentity = Field(serialization_alias="schema")
    parser: ParserIdentity
    claims: tuple[ByteClaim, ...]
    certificate_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @classmethod
    def build(
        cls,
        *,
        raw_event: RawEvent,
        claims: list[ByteClaim],
        schema: SchemaIdentity,
        parser: ParserIdentity,
        normalization_revision: int = 1,
    ) -> ConservationCertificate:
        if not raw_event.verify_integrity():
            raise ValueError("raw event failed its integrity check")
        ordered = sorted(claims, key=lambda claim: (claim.start, claim.end))
        complete: list[ByteClaim] = []
        cursor = 0
        for claim in ordered:
            if claim.end > len(raw_event.raw_bytes):
                raise ValueError("claim extends beyond the raw event")
            if claim.start < cursor:
                raise ValueError("byte claims must not overlap")
            fragment = raw_event.raw_bytes[claim.start : claim.end]
            if claim.fragment_sha256 != hashlib.sha256(fragment).hexdigest():
                raise ValueError("claim fragment digest does not match the raw event")
            if claim.start > cursor:
                complete.append(cls._gap_claim(raw_event.raw_bytes, cursor, claim.start))
            complete.append(claim)
            cursor = claim.end
        if cursor < len(raw_event.raw_bytes):
            complete.append(cls._gap_claim(raw_event.raw_bytes, cursor, len(raw_event.raw_bytes)))

        accounted = sum(
            claim.end - claim.start
            for claim in complete
            if claim.disposition is not ByteDisposition.UNMAPPED
        )
        total = len(raw_event.raw_bytes)
        score = 1.0 if total == 0 else accounted / total
        unsigned = {
            "raw_event_id": str(raw_event.event_id),
            "raw_sha256": raw_event.raw_sha256,
            "total_bytes": total,
            "accounted_bytes": accounted,
            "conservation_score": score,
            "fully_accounted": accounted == total,
            "normalization_revision": normalization_revision,
            "schema": schema.model_dump(mode="json"),
            "parser": parser.model_dump(mode="json"),
            "claims": [claim.model_dump(mode="json") for claim in complete],
        }
        certificate_sha256 = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return cls(
            raw_event_id=raw_event.event_id,
            raw_sha256=raw_event.raw_sha256,
            total_bytes=total,
            accounted_bytes=accounted,
            conservation_score=score,
            fully_accounted=accounted == total,
            normalization_revision=normalization_revision,
            schema_identity=schema,
            parser=parser,
            claims=tuple(complete),
            certificate_sha256=certificate_sha256,
        )

    def verify(self, raw_event: RawEvent) -> bool:
        try:
            rebuilt = self.build(
                raw_event=raw_event,
                claims=[claim for claim in self.claims if claim.rule_uid != "drishti.auto-gap"],
                schema=self.schema_identity,
                parser=self.parser,
                normalization_revision=self.normalization_revision,
            )
        except ValueError:
            return False
        return rebuilt == self

    @staticmethod
    def _gap_claim(raw: bytes, start: int, end: int) -> ByteClaim:
        return ByteClaim.from_raw(
            raw,
            start=start,
            end=end,
            disposition=ByteDisposition.UNMAPPED,
            rule_uid="drishti.auto-gap",
        )
