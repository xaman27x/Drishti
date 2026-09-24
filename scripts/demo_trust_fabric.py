#!/usr/bin/env python3
"""Demonstrate Drishti's adaptive trust fabric without external services."""

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
from drishti.trust.dialect import DialectDriftSentinel, DialectFingerprinter
from drishti.trust.federation import DialectCapsuleBuilder, FederationAggregator
from drishti.trust.shadow import PromotionPolicy, ShadowEvaluator, ShadowPromotionGate
from drishti.trust.transparency import MerkleTransparencyLog

FEDERATION_KEY = b"drishti-air-gap-federation-key"


def main() -> None:
    fingerprinter = DialectFingerprinter(FEDERATION_KEY)
    sentinel = DialectDriftSentinel(
        source_key="perimeter-firewall",
        fingerprinter=fingerprinter,
        baseline_size=4,
        window_size=2,
    )
    for _ in range(4):
        sentinel.observe(event_id=uuid4(), raw=RFC5424_FIREWALL_SAMPLE)
    sentinel.observe(event_id=uuid4(), raw=CEF_FIREWALL_SAMPLE)
    drift = sentinel.observe(event_id=uuid4(), raw=CEF_FIREWALL_SAMPLE)

    active_pack = rfc5424_firewall_pack()
    candidate_pack = active_pack.model_copy(update={"version": "1.1.0"})
    shadow = ShadowEvaluator(OcsfCatalog.load_packaged()).evaluate(
        active_pack=active_pack,
        candidate_pack=candidate_pack,
        events=[_raw_event() for _ in range(2)],
    )
    promotion = ShadowPromotionGate(PromotionPolicy(minimum_events=2)).decide(shadow)

    transparency_signer = ArtifactSigner.generate("demo-transparency-root")
    transparency_keys = _keyring(transparency_signer)
    transparency = MerkleTransparencyLog(
        log_id="drishti-trust-fabric", checkpoint_signer=transparency_signer
    )
    transparency.append(
        artifact_type="dialect-drift-decision",
        artifact_sha256=drift.fingerprint.fingerprint_hmac,
        metadata={"status": drift.status},
    )
    shadow_leaf = transparency.append(
        artifact_type="shadow-promotion-report",
        artifact_sha256=shadow.report_sha256,
        metadata={"accepted": promotion.accepted},
    )
    proof = transparency.inclusion_proof(shadow_leaf.index)
    checkpoint = transparency.checkpoint()

    site_a = ArtifactSigner.generate("demo-site-a")
    site_b = ArtifactSigner.generate("demo-site-b")
    federation_keys = _keyring(site_a)
    federation_keys.add_base64(site_b.key_id, site_b.public_key_base64())
    start = datetime(2026, 9, 26, 12, tzinfo=UTC)
    samples = [RFC5424_FIREWALL_SAMPLE] * 4
    capsule_a = DialectCapsuleBuilder(
        fingerprinter=fingerprinter, signer=site_a, k_anonymity=2
    ).build(
        site_pseudonym="north-zone-01",
        source_family="perimeter-firewall",
        window_start=start,
        window_end=start + timedelta(hours=1),
        samples=samples,
    )
    capsule_b = DialectCapsuleBuilder(
        fingerprinter=fingerprinter, signer=site_b, k_anonymity=2
    ).build(
        site_pseudonym="south-zone-02",
        source_family="perimeter-firewall",
        window_start=start,
        window_end=start + timedelta(hours=1),
        samples=samples,
    )
    federation = FederationAggregator(federation_keys)
    federation.ingest(capsule_a)
    insight = federation.ingest(capsule_b)
    capsule_json = capsule_a.model_dump_json()

    print(
        json.dumps(
            {
                "dialect_dna": {
                    "decision": drift.status,
                    "jensen_shannon_divergence": drift.js_divergence,
                    "raw_values_exported": "10.0.0.1" in drift.model_dump_json(),
                },
                "shadow_twin": {
                    "evaluated_events": shadow.total_events,
                    "critical_regressions": shadow.critical_regressions,
                    "conservation": shadow.minimum_candidate_conservation,
                    "promotion_accepted": promotion.accepted,
                    "report_sha256": shadow.report_sha256,
                },
                "transparency": {
                    "tree_size": checkpoint.tree_size,
                    "root_hash": checkpoint.root_hash,
                    "inclusion_verified": transparency.verify_inclusion(
                        shadow_leaf, proof, expected_root=checkpoint.root_hash
                    ),
                    "checkpoint_signature_verified": checkpoint.verify(transparency_keys),
                },
                "sovereign_federation": {
                    "participating_sites": insight.participating_sites,
                    "structural_similarity": insight.structural_similarity,
                    "novel_dialect": insight.novel_dialect,
                    "raw_values_exported": "10.0.0.1" in capsule_json,
                    "capsule_signature_verified": capsule_a.verify(federation_keys),
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
