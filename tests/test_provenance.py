from datetime import UTC, datetime
from uuid import uuid4

import pytest

from drishti.domain.events import RawEvent, SourceRef
from drishti.normalization.models import CertifiedNormalizedEvent, OcsfContractError
from drishti.ocsf.catalog import get_ocsf_catalog
from drishti.provenance.lineage import ByteClaim, ByteDisposition, ParserIdentity


def raw_event(raw: bytes) -> RawEvent:
    return RawEvent.create(
        event_id=uuid4(),
        trace_id=uuid4(),
        source=SourceRef(tenant_id="demo", source_id="fw-01", source_type="firewall"),
        raw_bytes=raw,
        idempotency_key="42",
        observed_at=None,
        received_at=datetime(2026, 9, 26, tzinfo=UTC),
    )


def parser_identity() -> ParserIdentity:
    return ParserIdentity(bundle_uid="demo-firewall@1.0.0", bundle_sha256="a" * 64)


def ocsf_network_event() -> dict[str, object]:
    return {
        "activity_id": 1,
        "category_uid": 4,
        "class_uid": 4001,
        "metadata": {"product": {"name": "Drishti"}, "version": "1.9.0"},
        "severity_id": 1,
        "src_endpoint": {"ip": "10.0.0.1", "uid": "10.0.0.1"},
        "time": 1_798_000_000_000,
        "type_uid": 400101,
    }


def test_certificate_fills_unmapped_gaps_and_verifies() -> None:
    raw = raw_event(b"src=10.0.0.1 action=allow")
    ip_start = raw.raw_bytes.index(b"10.0.0.1")
    claim = ByteClaim.from_raw(
        raw.raw_bytes,
        start=ip_start,
        end=ip_start + len(b"10.0.0.1"),
        disposition=ByteDisposition.MAPPED,
        rule_uid="demo.src-ip",
        target_path="src_endpoint.ip",
        transformation="parse_ip",
    )

    normalized = CertifiedNormalizedEvent.issue(
        raw_event=raw,
        ocsf_event=ocsf_network_event(),
        claims=[claim],
        parser=parser_identity(),
        catalog=get_ocsf_catalog(),
    )

    assert normalized.certificate.fully_accounted is False
    assert normalized.certificate.accounted_bytes == len(b"10.0.0.1")
    assert any(
        item.disposition is ByteDisposition.UNMAPPED for item in normalized.certificate.claims
    )
    assert normalized.verify(raw_event=raw, catalog=get_ocsf_catalog())


def test_certificate_rejects_overlapping_claims() -> None:
    raw = raw_event(b"abcdef")
    first = ByteClaim.from_raw(
        raw.raw_bytes,
        start=0,
        end=4,
        disposition=ByteDisposition.STRUCTURAL,
        rule_uid="demo.first",
    )
    second = ByteClaim.from_raw(
        raw.raw_bytes,
        start=3,
        end=6,
        disposition=ByteDisposition.STRUCTURAL,
        rule_uid="demo.second",
    )

    with pytest.raises(ValueError, match="must not overlap"):
        CertifiedNormalizedEvent.issue(
            raw_event=raw,
            ocsf_event=ocsf_network_event(),
            claims=[first, second],
            parser=parser_identity(),
            catalog=get_ocsf_catalog(),
        )


def test_certification_rejects_invalid_ocsf_before_issuing_proof() -> None:
    raw = raw_event(b"anything")
    invalid = ocsf_network_event()
    invalid["type_uid"] = 999

    with pytest.raises(OcsfContractError, match="type_uid"):
        CertifiedNormalizedEvent.issue(
            raw_event=raw,
            ocsf_event=invalid,
            claims=[],
            parser=parser_identity(),
            catalog=get_ocsf_catalog(),
        )
