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
from drishti.safety.format_detection import DriftStatus, FormatChangeDetector, FormatFingerprinter
from drishti.safety.format_sharing import FormatSummaryBuilder, FormatSummaryMatcher
from drishti.safety.parser_comparison import ParserComparator, ParserPromotionGate, PromotionPolicy
from drishti.safety.release_history import ReleaseHistory
from drishti.safety.routing import FormatAwareRouter, ProcessingRoute

SHARING_KEY = b"drishti-demo-format-sharing-key"


class RecordingRoutePublisher:
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


def test_format_change_is_detected_without_exporting_raw_values() -> None:
    detector = FormatChangeDetector(
        source_key="generic.perimeter-firewall",
        fingerprinter=FormatFingerprinter(SHARING_KEY),
        baseline_size=4,
        window_size=2,
    )
    for _ in range(4):
        decision = detector.observe(event_id=uuid4(), raw=RFC5424_FIREWALL_SAMPLE)
        assert decision.status is DriftStatus.LEARNING
    detector.observe(event_id=uuid4(), raw=CEF_FIREWALL_SAMPLE)
    changed = detector.observe(event_id=uuid4(), raw=CEF_FIREWALL_SAMPLE)

    assert changed.status is DriftStatus.QUARANTINE
    assert changed.js_divergence == 1.0
    serialized = changed.model_dump_json()
    assert "10.0.0.1" not in serialized
    assert "Allowed TLS" not in serialized


@pytest.mark.asyncio
async def test_drift_router_quarantines_without_losing_or_mutating_evidence() -> None:
    detector = FormatChangeDetector(
        source_key="generic.perimeter-firewall",
        fingerprinter=FormatFingerprinter(SHARING_KEY),
        baseline_size=4,
        window_size=2,
    )
    publisher = RecordingRoutePublisher()
    router = FormatAwareRouter(detector=detector, publisher=publisher)
    for _ in range(4):
        await router.route(_raw_event(RFC5424_FIREWALL_SAMPLE))
    await router.route(_raw_event(CEF_FIREWALL_SAMPLE))
    changed = _raw_event(CEF_FIREWALL_SAMPLE)
    receipt = await router.route(changed)

    assert receipt.routes == (ProcessingRoute.QUARANTINE,)
    assert publisher.quarantined == [changed]
    assert publisher.quarantined[0].verify_integrity()
    assert publisher.quarantined[0].raw_sha256 == changed.raw_sha256


def test_parser_comparison_accepts_equivalent_upgrade_and_rejects_regression() -> None:
    catalog = OcsfCatalog.load_packaged()
    active = rfc5424_firewall_pack()
    equivalent = active.model_copy(update={"version": "1.1.0"})
    events = [_raw_event(RFC5424_FIREWALL_SAMPLE) for _ in range(2)]
    evaluator = ParserComparator(catalog)
    gate = ParserPromotionGate(PromotionPolicy(minimum_events=2))

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


def test_release_history_proofs_and_signed_checkpoint_are_offline_verifiable() -> None:
    signer = ArtifactSigner.generate("release-history-root")
    keys = PublicKeyRing()
    keys.add_base64(signer.key_id, signer.public_key_base64())
    log = ReleaseHistory(log_id="drishti-parser-releases", checkpoint_signer=signer)
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


def test_signed_format_summaries_can_be_compared_without_raw_logs() -> None:
    fingerprinter = FormatFingerprinter(SHARING_KEY)
    site_a = ArtifactSigner.generate("site-a")
    site_b = ArtifactSigner.generate("site-b")
    trusted = PublicKeyRing()
    trusted.add_base64(site_a.key_id, site_a.public_key_base64())
    trusted.add_base64(site_b.key_id, site_b.public_key_base64())
    start = datetime(2026, 9, 26, 10, tzinfo=UTC)
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
    serialized = summary_a.model_dump_json()
    assert "10.0.0.1" not in serialized
    assert "edge-fw-01" not in serialized
    assert summary_a.verify(trusted)

    matcher = FormatSummaryMatcher(trusted)
    first = matcher.ingest(summary_a)
    second = matcher.ingest(summary_b)
    assert first.unknown_format
    assert not second.unknown_format
    assert second.structural_similarity == 1.0
    assert second.participating_sites == 2


@pytest.mark.asyncio
async def test_parser_upgrade_requires_comparison_and_enters_release_history() -> None:
    catalog = OcsfCatalog.load_packaged()
    parser_signer = ArtifactSigner.generate("parser-authority")
    reviewer = ArtifactSigner.generate("reviewer")
    registry_signer = ArtifactSigner.generate("registry-root")
    history_signer = ArtifactSigner.generate("release-history-root")
    parser_keys = PublicKeyRing()
    parser_keys.add_base64(parser_signer.key_id, parser_signer.public_key_base64())
    reviewer_keys = PublicKeyRing()
    reviewer_keys.add_base64(reviewer.key_id, reviewer.public_key_base64())
    history_keys = PublicKeyRing()
    history_keys.add_base64(
        history_signer.key_id, history_signer.public_key_base64()
    )
    release_history = ReleaseHistory(
        log_id="drishti-parser-releases", checkpoint_signer=history_signer
    )
    registry = ParserRegistry(
        registry_signer=registry_signer,
        parser_keys=parser_keys,
        reviewer_keys=reviewer_keys,
        release_history=release_history,
    )
    control = ParserControlPlane(
        registry=registry,
        qualification_gate=QualificationGate(catalog),
        parser_signer=parser_signer,
        promotion_gate=ParserPromotionGate(PromotionPolicy(minimum_events=2)),
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
    with pytest.raises(ValueError, match="comparison report"):
        await control.activate(proposal_id=second_id, actor_id="release-bot")

    report = ParserComparator(catalog).evaluate(
        active_pack=active_pack,
        candidate_pack=candidate,
        events=[_raw_event(RFC5424_FIREWALL_SAMPLE) for _ in range(2)],
    )
    second = await control.activate(
        proposal_id=second_id,
        actor_id="release-bot",
        comparison_report=report,
    )
    release = registry.release_at(second.release_revision or 0)
    leaf, proof, checkpoint = registry.release_evidence(release.registry_revision)

    assert release.comparison_report_sha256 == report.report_sha256
    assert registry.verify_history()
    assert release_history.verify_inclusion(leaf, proof, expected_root=checkpoint.root_hash)
    assert checkpoint.verify(history_keys)
