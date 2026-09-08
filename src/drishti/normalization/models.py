from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict

from drishti.domain.events import RawEvent
from drishti.ocsf.catalog import OcsfCatalog
from drishti.provenance.lineage import ByteClaim, ConservationCertificate, ParserIdentity


class OcsfContractError(ValueError):
    """Raised when a candidate normalized event violates its pinned OCSF contract."""


class CertifiedNormalizedEvent(BaseModel):
    """Immutable OCSF event plus the proof needed to reproduce and audit it."""

    model_config = ConfigDict(frozen=True)

    normalized_event_id: UUID
    raw_event_id: UUID
    created_at: datetime
    ocsf_event: dict[str, Any]
    certificate: ConservationCertificate

    @classmethod
    def issue(
        cls,
        *,
        raw_event: RawEvent,
        ocsf_event: dict[str, Any],
        claims: list[ByteClaim],
        parser: ParserIdentity,
        catalog: OcsfCatalog,
        normalization_revision: int = 1,
    ) -> CertifiedNormalizedEvent:
        report = catalog.validate(ocsf_event)
        if not report.valid:
            summary = "; ".join(f"{issue.path}: {issue.message}" for issue in report.issues)
            raise OcsfContractError(summary)
        certificate = ConservationCertificate.build(
            raw_event=raw_event,
            claims=claims,
            schema=catalog.identity,
            parser=parser,
            normalization_revision=normalization_revision,
        )
        identity_material = (
            f"{raw_event.event_id}:{parser.bundle_sha256}:"
            f"{catalog.identity.bundle_sha256}:{normalization_revision}"
        )
        return cls(
            normalized_event_id=uuid5(NAMESPACE_URL, identity_material),
            raw_event_id=raw_event.event_id,
            created_at=datetime.now(UTC),
            ocsf_event=ocsf_event,
            certificate=certificate,
        )

    def verify(self, *, raw_event: RawEvent, catalog: OcsfCatalog) -> bool:
        if raw_event.event_id != self.raw_event_id:
            return False
        if catalog.identity != self.certificate.schema_identity:
            return False
        if not catalog.validate(self.ocsf_event).valid:
            return False
        return self.certificate.verify(raw_event)
