#!/usr/bin/env python3
"""Run Drishti's complete governed parser and controlled replay story locally."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from uuid import uuid4

from drishti.adapters.memory import InMemoryNormalizedEventSink, InMemoryRawEvidenceStore
from drishti.copilot.local import AirGappedSchemaCopilot
from drishti.domain.events import RawEvent, SourceRef
from drishti.governance.crypto import ArtifactSigner, PublicKeyRing
from drishti.governance.qualification import QualificationGate
from drishti.governance.registry import ParserRegistry, ReviewDecision
from drishti.governance.workflow import ParserControlPlane
from drishti.ocsf.catalog import OcsfCatalog
from drishti.parsers.builtin import RFC5424_FIREWALL_SAMPLE
from drishti.replay.models import ReplayManifest
from drishti.replay.worker import ControlledReplayWorker


async def main() -> None:
    catalog = OcsfCatalog.load_packaged()
    parser_signer = ArtifactSigner.generate("demo-parser-authority")
    registry_signer = ArtifactSigner.generate("demo-registry-root")
    reviewer_signer = ArtifactSigner.generate("demo-reviewer")
    replay_signer = ArtifactSigner.generate("demo-incident-commander")

    parser_keys = _keyring(parser_signer)
    reviewer_keys = _keyring(reviewer_signer)
    registry = ParserRegistry(
        registry_signer=registry_signer,
        parser_keys=parser_keys,
        reviewer_keys=reviewer_keys,
    )
    control = ParserControlPlane(
        registry=registry,
        qualification_gate=QualificationGate(catalog),
        parser_signer=parser_signer,
    )

    suggestion = AirGappedSchemaCopilot().propose([RFC5424_FIREWALL_SAMPLE])
    proposal = control.submit(pack=suggestion.pack, proposed_by="local-copilot")
    control.review(
        proposal_id=proposal.proposal_id,
        reviewer_id=reviewer_signer.key_id,
        reviewer_signer=reviewer_signer,
        decision=ReviewDecision.APPROVE,
        reason="sample grammar, field semantics, and OCSF targets verified",
    )
    qualified = control.qualify(proposal_id=proposal.proposal_id, actor_id="qualification-runner")
    active = await control.activate(
        proposal_id=proposal.proposal_id, actor_id="registry-release-bot"
    )

    evidence = InMemoryRawEvidenceStore()
    raw_event = RawEvent.create(
        event_id=uuid4(),
        trace_id=uuid4(),
        source=SourceRef(
            tenant_id="sih-demo",
            source_id="edge-fw-01",
            source_type=suggestion.pack.source_key,
        ),
        raw_bytes=RFC5424_FIREWALL_SAMPLE,
        idempotency_key="demo-event-1",
        observed_at=None,
        received_at=datetime.now(UTC),
    )
    await evidence.put_if_absent(raw_event)
    manifest = ReplayManifest.issue(
        source_key=suggestion.pack.source_key,
        registry_revision=active.release_revision or 0,
        pack_sha256=suggestion.pack.sha256(),
        event_ids=(raw_event.event_id,),
        normalization_revision=2,
        reason="demonstrate approved re-normalization over immutable evidence",
        requested_by="demo-soc-analyst",
        approved_by=replay_signer.key_id,
        approver_signer=replay_signer,
    )
    sink = InMemoryNormalizedEventSink()
    replay = await ControlledReplayWorker(
        registry=registry,
        catalog=catalog,
        evidence=evidence,
        sink=sink,
        replay_approver_keys=_keyring(replay_signer),
    ).run(manifest)
    normalized = next(iter(sink.events.values()))
    print(
        json.dumps(
            {
                "copilot": {
                    "format": suggestion.detected_format,
                    "confidence": suggestion.confidence,
                    "unknown_captures": suggestion.unknown_captures,
                },
                "governance": {
                    "proposal_status": active.status,
                    "qualification_passed": qualified.qualification.passed
                    if qualified.qualification
                    else False,
                    "registry_revision": active.release_revision,
                    "registry_verified": registry.verify_history(),
                    "audit_chain_verified": control.audit_log.verify(),
                },
                "replay": {
                    "result": replay.results[0].status,
                    "raw_sha256": raw_event.raw_sha256,
                    "normalized_event_id": str(normalized.normalized_event_id),
                    "normalization_revision": normalized.certificate.normalization_revision,
                    "conservation_score": normalized.certificate.conservation_score,
                    "certificate_sha256": normalized.certificate.certificate_sha256,
                },
                "ocsf_event": normalized.ocsf_event,
            },
            indent=2,
            default=str,
        )
    )


def _keyring(signer: ArtifactSigner) -> PublicKeyRing:
    keyring = PublicKeyRing()
    keyring.add_base64(signer.key_id, signer.public_key_base64())
    return keyring


if __name__ == "__main__":
    asyncio.run(main())
