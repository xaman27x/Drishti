from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from drishti.domain.events import RawEvent, SourceRef
from drishti.ocsf.catalog import OcsfCatalog
from drishti.parsers.builtin import (
    CEF_FIREWALL_SAMPLE,
    RFC5424_FIREWALL_SAMPLE,
    cef_firewall_pack,
    rfc5424_firewall_pack,
)
from drishti.parsers.cef import CefParser
from drishti.parsers.common import ParseError
from drishti.parsers.engine import DeterministicParserEngine
from drishti.provenance.lineage import ByteDisposition, ParserIdentity


@pytest.fixture(scope="module")
def engine() -> DeterministicParserEngine:
    return DeterministicParserEngine(OcsfCatalog.load_packaged())


@pytest.mark.parametrize(
    ("raw", "pack_factory"),
    [
        (RFC5424_FIREWALL_SAMPLE, rfc5424_firewall_pack),
        (CEF_FIREWALL_SAMPLE, cef_firewall_pack),
    ],
)
def test_builtin_pack_produces_valid_lossless_ocsf_event(
    engine: DeterministicParserEngine, raw: bytes, pack_factory: object
) -> None:
    pack = pack_factory()  # type: ignore[operator]
    raw_event = RawEvent.create(
        event_id=uuid4(),
        trace_id=uuid4(),
        source=SourceRef(tenant_id="test", source_id="fw-1"),
        raw_bytes=raw,
        idempotency_key=None,
        observed_at=None,
        received_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    normalized = engine.normalize(
        raw_event=raw_event,
        pack=pack,
        parser_identity=ParserIdentity(
            bundle_uid=pack.pack_uid,
            bundle_sha256=pack.sha256(),
        ),
    )

    assert normalized.verify(raw_event=raw_event, catalog=OcsfCatalog.load_packaged())
    assert normalized.certificate.fully_accounted
    assert normalized.certificate.conservation_score == 1.0
    assert any(
        claim.disposition is ByteDisposition.MAPPED for claim in normalized.certificate.claims
    )


def test_cef_parser_handles_escaped_header_delimiter() -> None:
    parsed = CefParser().parse(b"CEF:0|Acme\\|Labs|Edge|1|42|Allowed|5|src=10.0.0.1")
    assert parsed.captures["device.vendor"] == "Acme|Labs"
    assert parsed.captures["ext.src"] == "10.0.0.1"


@pytest.mark.parametrize(
    "raw",
    [
        b"CEF:0|vendor|product",
        b"<999>1 2026-01-01T00:00:00Z host app 1 msg - value=1",
        b"\xff\xfe",
    ],
)
def test_malformed_input_fails_closed(engine: DeterministicParserEngine, raw: bytes) -> None:
    with pytest.raises((ParseError, UnicodeDecodeError)):
        engine.parse(
            raw, cef_firewall_pack() if raw.startswith(b"CEF") else rfc5424_firewall_pack()
        )
