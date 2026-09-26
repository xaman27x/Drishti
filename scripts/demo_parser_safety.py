#!/usr/bin/env python3
"""Demonstrate Drishti's parser safety controls without external services."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from drishti.domain.events import RawEvent, SourceRef
from drishti.governance.crypto import ArtifactSigner, PublicKeyRing
from drishti.ocsf.catalog import OcsfCatalog
from drishti.parsers.builtin import (
    CEF_FIREWALL_SAMPLE,
    RFC5424_FIREWALL_SAMPLE,
    rfc5424_firewall_pack,
)
from drishti.safety.format_detection import FormatChangeDetector, FormatFingerprinter
from drishti.safety.format_sharing import FormatSummaryBuilder, FormatSummaryMatcher
from drishti.safety.parser_comparison import ParserComparator, ParserPromotionGate, PromotionPolicy
from drishti.safety.release_history import ReleaseHistory

SHARING_KEY = b"drishti-air-gap-format-sharing-key"


def main() -> None:
    fingerprinter = FormatFingerprinter(SHARING_KEY)
    detector = FormatChangeDetector(
        source_key="perimeter-firewall",
        fingerprinter=fingerprinter,
        baseline_size=4,
        window_size=2,
    )
    for _ in range(4):
        detector.observe(event_id=uuid4(), raw=RFC5424_FIREWALL_SAMPLE)
    detector.observe(event_id=uuid4(), raw=CEF_FIREWALL_SAMPLE)
    format_change = detector.observe(event_id=uuid4(), raw=CEF_FIREWALL_SAMPLE)

    active_pack = rfc5424_firewall_pack()
    candidate_pack = active_pack.model_copy(update={"version": "1.1.0"})
    comparison = ParserComparator(OcsfCatalog.load_packaged()).evaluate(
        active_pack=active_pack,
        candidate_pack=candidate_pack,
        events=[_raw_event() for _ in range(2)],
    )
    promotion = ParserPromotionGate(PromotionPolicy(minimum_events=2)).decide(comparison)

    history_signer = ArtifactSigner.generate("demo-release-history-root")
    history_keys = _keyring(history_signer)
    release_history = ReleaseHistory(
        log_id="drishti-parser-releases", checkpoint_signer=history_signer
    )
    release_history.append(
        artifact_type="format-change-decision",
        artifact_sha256=format_change.fingerprint.fingerprint_hmac,
        metadata={"status": format_change.status},
    )
    comparison_record = release_history.append(
        artifact_type="parser-comparison-report",
        artifact_sha256=comparison.report_sha256,
        metadata={"accepted": promotion.accepted},
    )
    proof = release_history.inclusion_proof(comparison_record.index)
    checkpoint = release_history.checkpoint()

    site_a = ArtifactSigner.generate("demo-site-a")
    site_b = ArtifactSigner.generate("demo-site-b")
    site_keys = _keyring(site_a)
    site_keys.add_base64(site_b.key_id, site_b.public_key_base64())
    start = datetime(2026, 9, 26, 12, tzinfo=UTC)
    samples = [RFC5424_FIREWALL_SAMPLE] * 4
    summary_a = FormatSummaryBuilder(
        fingerprinter=fingerprinter, signer=site_a, k_anonymity=2
    ).build(
        site_pseudonym="north-zone-01",
        source_family="perimeter-firewall",
        window_start=start,
        window_end=start + timedelta(hours=1),
        samples=samples,
    )
    summary_b = FormatSummaryBuilder(
        fingerprinter=fingerprinter, signer=site_b, k_anonymity=2
    ).build(
        site_pseudonym="south-zone-02",
        source_family="perimeter-firewall",
        window_start=start,
        window_end=start + timedelta(hours=1),
        samples=samples,
    )
    matcher = FormatSummaryMatcher(site_keys)
    matcher.ingest(summary_a)
    match = matcher.ingest(summary_b)
    summary_json = summary_a.model_dump_json()

    print(
        json.dumps(
            {
                "format_change_detection": {
                    "decision": format_change.status,
                    "jensen_shannon_divergence": format_change.js_divergence,
                    "raw_values_exported": "10.0.0.1" in format_change.model_dump_json(),
                },
                "parser_comparison": {
                    "evaluated_events": comparison.total_events,
                    "critical_regressions": comparison.critical_regressions,
                    "conservation": comparison.minimum_candidate_conservation,
                    "promotion_accepted": promotion.accepted,
                    "report_sha256": comparison.report_sha256,
                },
                "release_history": {
                    "tree_size": checkpoint.tree_size,
                    "root_hash": checkpoint.root_hash,
                    "inclusion_verified": release_history.verify_inclusion(
                        comparison_record, proof, expected_root=checkpoint.root_hash
                    ),
                    "checkpoint_signature_verified": checkpoint.verify(history_keys),
                },
                "cross_site_format_sharing": {
                    "participating_sites": match.participating_sites,
                    "structural_similarity": match.structural_similarity,
                    "unknown_format": match.unknown_format,
                    "raw_values_exported": "10.0.0.1" in summary_json,
                    "summary_signature_verified": summary_a.verify(site_keys),
                },
            },
            indent=2,
            default=str,
        )
    )


def _raw_event() -> RawEvent:
    return RawEvent.create(
        event_id=uuid4(),
        trace_id=uuid4(),
        source=SourceRef(
            tenant_id="sih-demo",
            source_id="edge-fw-01",
            source_type="generic.rfc5424-firewall",
        ),
        raw_bytes=RFC5424_FIREWALL_SAMPLE,
        idempotency_key=None,
        observed_at=None,
    )


def _keyring(signer: ArtifactSigner) -> PublicKeyRing:
    keyring = PublicKeyRing()
    keyring.add_base64(signer.key_id, signer.public_key_base64())
    return keyring


if __name__ == "__main__":
    main()
