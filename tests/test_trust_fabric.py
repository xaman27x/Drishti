from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from drishti.domain.events import RawEvent, SourceRef
from drishti.governance.crypto import ArtifactSigner, PublicKeyRing
from drishti.governance.qualification import QualificationGate
from drishti.governance.registry import ParserRegistry, ReviewDecision
from drishti.governance.workflow import ParserControlPlane, ProposalStatus
from drishti.ocsf.catalog import OcsfCatalog
from drishti.parsers.builtin import (
    CEF_FIREWALL_SAMPLE,
    RFC5424_FIREWALL_SAMPLE,
    rfc5424_firewall_pack,
)
from drishti.parsers.models import SourceDefinitionPack
from drishti.trust.dialect import DialectDriftSentinel, DialectFingerprinter, DriftStatus
from drishti.trust.federation import DialectCapsuleBuilder, FederationAggregator
from drishti.trust.routing import AdaptiveTrustRouter, TrustRoute
from drishti.trust.shadow import PromotionPolicy, ShadowEvaluator, ShadowPromotionGate
from drishti.trust.transparency import MerkleTransparencyLog

FEDERATION_KEY = b"drishti-demo-federation-key-32b"


class RecordingTrustPublisher:
    def __init__(self) -> None:
        self.active: list[RawEvent] = []
        self.review: list[RawEvent] = []
        self.quarantined: list[RawEvent] = []

    async def publish_active(self, event: RawEvent, decision: object) -> None:
        self.active.append(event)

    async def publish_review(self, event: RawEvent, decision: object) -> None:
        self.review.append(event)

    async def publish_quarantine(self, event: RawEvent, decision: object) -> None:
        self.quarantined.append(event)


def _raw_event(raw: bytes) -> RawEvent:
    return RawEvent.create(
        event_id=uuid4(),
        trace_id=uuid4(),
        source=SourceRef(
            tenant_id="trust-test",
            source_id="edge-fw-01",
            source_type="generic.rfc5424-firewall",
        ),
        raw_bytes=raw,
        idempotency_key=None,
        observed_at=None,
        received_at=datetime(2026, 9, 26, tzinfo=UTC),
    )


def test_dialect_dna_detects_firmware_format_drift_without_exporting_raw_values() -> None:
    sentinel = DialectDriftSentinel(
        source_key="generic.perimeter-firewall",
        fingerprinter=DialectFingerprinter(FEDERATION_KEY),
        baseline_size=4,
        window_size=2,
    )
    for _ in range(4):
        decision = sentinel.observe(event_id=uuid4(), raw=RFC5424_FIREWALL_SAMPLE)
        assert decision.status is DriftStatus.LEARNING
    sentinel.observe(event_id=uuid4(), raw=CEF_FIREWALL_SAMPLE)
    changed = sentinel.observe(event_id=uuid4(), raw=CEF_FIREWALL_SAMPLE)

    assert changed.status is DriftStatus.QUARANTINE
    assert changed.js_divergence == 1.0
    serialized = changed.model_dump_json()
    assert "10.0.0.1" not in serialized
    assert "Allowed TLS" not in serialized


@pytest.mark.asyncio
async def test_drift_router_quarantines_without_losing_or_mutating_evidence() -> None:
    sentinel = DialectDriftSentinel(
        source_key="generic.perimeter-firewall",
        fingerprinter=DialectFingerprinter(FEDERATION_KEY),
        baseline_size=4,
        window_size=2,
    )
    publisher = RecordingTrustPublisher()
    router = AdaptiveTrustRouter(sentinel=sentinel, publisher=publisher)
    for _ in range(4):
        await router.route(_raw_event(RFC5424_FIREWALL_SAMPLE))
    await router.route(_raw_event(CEF_FIREWALL_SAMPLE))
    changed = _raw_event(CEF_FIREWALL_SAMPLE)
    receipt = await router.route(changed)

    assert receipt.routes == (TrustRoute.QUARANTINE,)
    assert publisher.quarantined == [changed]
    assert publisher.quarantined[0].verify_integrity()
    assert publisher.quarantined[0].raw_sha256 == changed.raw_sha256


def test_shadow_twin_accepts_equivalent_upgrade_and_rejects_critical_regression() -> None:
    catalog = OcsfCatalog.load_packaged()
    active = rfc5424_firewall_pack()
    equivalent = active.model_copy(update={"version": "1.1.0"})
    events = [_raw_event(RFC5424_FIREWALL_SAMPLE) for _ in range(2)]
    evaluator = ShadowEvaluator(catalog)
    gate = ShadowPromotionGate(PromotionPolicy(minimum_events=2))

    safe_report = evaluator.evaluate(
        active_pack=active,
        candidate_pack=equivalent,
        events=events,
    )
    assert safe_report.verify()
    assert gate.decide(safe_report).accepted

    degraded = equivalent.model_copy(
        update={
            "version": "1.2.0",
            "rules": tuple(
                rule for rule in equivalent.rules if rule.target_path != "src_endpoint.ip"
            ),
        }
    )
    degraded_report = evaluator.evaluate(
        active_pack=active,
        candidate_pack=degraded,
        events=events,
    )
    rejected = gate.decide(degraded_report)
    assert not rejected.accepted
    assert degraded_report.critical_regressions == 2


def test_merkle_transparency_proofs_and_signed_checkpoint_are_offline_verifiable() -> None:
    signer = ArtifactSigner.generate("transparency-root")
    keys = PublicKeyRing()
    keys.add_base64(signer.key_id, signer.public_key_base64())
    log = MerkleTransparencyLog(log_id="drishti-parser-log", checkpoint_signer=signer)
    leaves = [
        log.append(
            artifact_type="parser-pack",
            artifact_sha256=f"{index:064x}",
            metadata={"sequence": index},
        )
        for index in range(1, 6)
    ]

    checkpoint = log.checkpoint()
    assert checkpoint.verify(keys)
    for leaf in leaves:
        proof = log.inclusion_proof(leaf.index)
        assert log.verify_inclusion(leaf, proof, expected_root=checkpoint.root_hash)
    tampered = leaves[2].model_copy(update={"artifact_sha256": "f" * 64})
    assert not log.verify_inclusion(tampered, log.inclusion_proof(2))


def test_signed_k_anonymous_capsules_correlate_dialects_without_raw_logs() -> None:
    fingerprinter = DialectFingerprinter(FEDERATION_KEY)
    site_a = ArtifactSigner.generate("site-a")
    site_b = ArtifactSigner.generate("site-b")
    trusted = PublicKeyRing()
    trusted.add_base64(site_a.key_id, site_a.public_key_base64())
    trusted.add_base64(site_b.key_id, site_b.public_key_base64())
    start = datetime(2026, 9, 26, 10, tzinfo=UTC)
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
    serialized = capsule_a.model_dump_json()
    assert "10.0.0.1" not in serialized
    assert "edge-fw-01" not in serialized
    assert capsule_a.verify(trusted)

    federation = FederationAggregator(trusted)
    first = federation.ingest(capsule_a)
    second = federation.ingest(capsule_b)
    assert first.novel_dialect
    assert not second.novel_dialect
    assert second.structural_similarity == 1.0
    assert second.participating_sites == 2


@pytest.mark.asyncio
async def test_parser_upgrade_requires_shadow_evidence_and_enters_transparency_log() -> None:
    catalog = OcsfCatalog.load_packaged()
    parser_signer = ArtifactSigner.generate("parser-authority")
    reviewer = ArtifactSigner.generate("reviewer")
    registry_signer = ArtifactSigner.generate("registry-root")
    transparency_signer = ArtifactSigner.generate("transparency-root")
    parser_keys = PublicKeyRing()
    parser_keys.add_base64(parser_signer.key_id, parser_signer.public_key_base64())
    reviewer_keys = PublicKeyRing()
    reviewer_keys.add_base64(reviewer.key_id, reviewer.public_key_base64())
    transparency_keys = PublicKeyRing()
    transparency_keys.add_base64(
        transparency_signer.key_id, transparency_signer.public_key_base64()
    )
    transparency = MerkleTransparencyLog(
        log_id="drishti-parser-log", checkpoint_signer=transparency_signer
    )
    registry = ParserRegistry(
        registry_signer=registry_signer,
        parser_keys=parser_keys,
        reviewer_keys=reviewer_keys,
        transparency_log=transparency,
    )
    control = ParserControlPlane(
        registry=registry,
        qualification_gate=QualificationGate(catalog),
        parser_signer=parser_signer,
        promotion_gate=ShadowPromotionGate(PromotionPolicy(minimum_events=2)),
    )

    async def approve_qualify(pack: SourceDefinitionPack) -> str:
        proposal = control.submit(pack=pack, proposed_by="copilot")
        control.review(
            proposal_id=proposal.proposal_id,
            reviewer_id=reviewer.key_id,
            reviewer_signer=reviewer,
            decision=ReviewDecision.APPROVE,
            reason="independent mapping review completed",
        )
        control.qualify(proposal_id=proposal.proposal_id, actor_id="qualifier")
        return proposal.proposal_id

    active_pack = rfc5424_firewall_pack()
    first_id = await approve_qualify(active_pack)
    first = await control.activate(proposal_id=first_id, actor_id="release-bot")
    assert first.status is ProposalStatus.ACTIVE

    candidate = active_pack.model_copy(update={"version": "1.1.0"})
    second_id = await approve_qualify(candidate)
    with pytest.raises(ValueError, match="shadow evidence"):
        await control.activate(proposal_id=second_id, actor_id="release-bot")

    report = ShadowEvaluator(catalog).evaluate(
        active_pack=active_pack,
        candidate_pack=candidate,
        events=[_raw_event(RFC5424_FIREWALL_SAMPLE) for _ in range(2)],
    )
    second = await control.activate(
        proposal_id=second_id,
        actor_id="release-bot",
        shadow_report=report,
    )
    release = registry.release_at(second.release_revision or 0)
    leaf, proof, checkpoint = registry.transparency_evidence(release.registry_revision)

    assert release.shadow_report_sha256 == report.report_sha256
    assert registry.verify_history()
    assert transparency.verify_inclusion(leaf, proof, expected_root=checkpoint.root_hash)
    assert checkpoint.verify(transparency_keys)
