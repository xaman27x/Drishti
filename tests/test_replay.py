from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from drishti.adapters.memory import InMemoryNormalizedEventSink, InMemoryRawEvidenceStore
from drishti.domain.events import RawEvent, SourceRef
from drishti.governance.crypto import ArtifactSigner, PublicKeyRing
from drishti.governance.qualification import QualificationGate
from drishti.governance.registry import ParserRegistry, ReviewDecision
from drishti.governance.workflow import ParserControlPlane
from drishti.ocsf.catalog import OcsfCatalog
from drishti.parsers.builtin import RFC5424_FIREWALL_SAMPLE, rfc5424_firewall_pack
from drishti.replay.models import ReplayEventStatus, ReplayManifest
from drishti.replay.worker import ControlledReplayWorker


@pytest.mark.asyncio
async def test_controlled_replay_is_signed_bounded_and_revision_pinned() -> None:
    parser_signer = ArtifactSigner.generate("parser-authority")
    registry_signer = ArtifactSigner.generate("registry-root")
    reviewer = ArtifactSigner.generate("reviewer-7")
    parser_keys = PublicKeyRing()
    parser_keys.add_base64(parser_signer.key_id, parser_signer.public_key_base64())
    reviewer_keys = PublicKeyRing()
    reviewer_keys.add_base64(reviewer.key_id, reviewer.public_key_base64())
    registry = ParserRegistry(
        registry_signer=registry_signer,
        parser_keys=parser_keys,
        reviewer_keys=reviewer_keys,
    )
    control = ParserControlPlane(
        registry=registry,
        qualification_gate=QualificationGate(OcsfCatalog.load_packaged()),
        parser_signer=parser_signer,
    )
    proposal = control.submit(pack=rfc5424_firewall_pack(), proposed_by="copilot")
    control.review(
        proposal_id=proposal.proposal_id,
        reviewer_id=reviewer.key_id,
        reviewer_signer=reviewer,
        decision=ReviewDecision.APPROVE,
        reason="fixture and mappings reviewed",
    )
    control.qualify(proposal_id=proposal.proposal_id, actor_id="qualifier")
    active = await control.activate(proposal_id=proposal.proposal_id, actor_id="release-bot")

    evidence = InMemoryRawEvidenceStore()
    event = RawEvent.create(
        event_id=uuid4(),
        trace_id=uuid4(),
        source=SourceRef(
            tenant_id="demo",
            source_id="edge-fw-01",
            source_type=proposal.pack.source_key,
        ),
        raw_bytes=RFC5424_FIREWALL_SAMPLE,
        idempotency_key=None,
        observed_at=None,
        received_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    await evidence.put_if_absent(event)
    replay_approver = ArtifactSigner.generate("incident-commander")
    replay_keys = PublicKeyRing()
    replay_keys.add_base64(replay_approver.key_id, replay_approver.public_key_base64())
    manifest = ReplayManifest.issue(
        source_key=proposal.pack.source_key,
        registry_revision=active.release_revision or 0,
        pack_sha256=proposal.pack.sha256(),
        event_ids=(event.event_id,),
        normalization_revision=2,
        reason="reprocess after validated mapping correction",
        requested_by="soc-analyst",
        approved_by=replay_approver.key_id,
        approver_signer=replay_approver,
    )
    sink = InMemoryNormalizedEventSink()
    worker = ControlledReplayWorker(
        registry=registry,
        catalog=OcsfCatalog.load_packaged(),
        evidence=evidence,
        sink=sink,
        replay_approver_keys=replay_keys,
    )
    result = await worker.run(manifest)

    assert result.results[0].status is ReplayEventStatus.NORMALIZED
    assert len(sink.events) == 1
    normalized = next(iter(sink.events.values()))
    assert normalized.raw_event_id == event.event_id
    assert normalized.certificate.normalization_revision == 2


def test_replay_manifest_forbids_self_approval() -> None:
    signer = ArtifactSigner.generate("same-person")
    with pytest.raises(ValueError, match="different people"):
        ReplayManifest.issue(
            source_key="generic.rfc5424-firewall",
            registry_revision=1,
            pack_sha256="a" * 64,
            event_ids=(uuid4(),),
            normalization_revision=2,
            reason="bounded replay for incident investigation",
            requested_by="same-person",
            approved_by="same-person",
            approver_signer=signer,
        )
