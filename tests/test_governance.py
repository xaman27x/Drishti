from __future__ import annotations

import pytest

from drishti.governance.audit import AppendOnlyAuditLog
from drishti.governance.crypto import ArtifactSigner, PublicKeyRing, SignedSourceDefinitionPack
from drishti.governance.qualification import QualificationGate
from drishti.governance.registry import ParserRegistry, ReviewDecision
from drishti.governance.workflow import ParserControlPlane, ProposalStatus
from drishti.ocsf.catalog import OcsfCatalog
from drishti.parsers.builtin import rfc5424_firewall_pack


def _control_plane() -> tuple[ParserControlPlane, ParserRegistry, ArtifactSigner]:
    parser_signer = ArtifactSigner.generate("parser-authority")
    reviewer_signer = ArtifactSigner.generate("reviewer-7")
    registry_signer = ArtifactSigner.generate("registry-root")
    parser_keys = PublicKeyRing()
    parser_keys.add_base64(parser_signer.key_id, parser_signer.public_key_base64())
    reviewer_keys = PublicKeyRing()
    reviewer_keys.add_base64(reviewer_signer.key_id, reviewer_signer.public_key_base64())
    registry = ParserRegistry(
        registry_signer=registry_signer,
        parser_keys=parser_keys,
        reviewer_keys=reviewer_keys,
    )
    return (
        ParserControlPlane(
            registry=registry,
            qualification_gate=QualificationGate(OcsfCatalog.load_packaged()),
            parser_signer=parser_signer,
        ),
        registry,
        reviewer_signer,
    )


def test_pack_signature_detects_tampering() -> None:
    signer = ArtifactSigner.generate("parser-authority")
    keys = PublicKeyRing()
    keys.add_base64(signer.key_id, signer.public_key_base64())
    signed = SignedSourceDefinitionPack.issue(rfc5424_firewall_pack(), signer=signer)

    assert signed.verify(keys)
    tampered = signed.model_copy(
        update={"pack": signed.pack.model_copy(update={"display_name": "Tampered"})}
    )
    assert not tampered.verify(keys)


def test_qualification_runs_contract_fixture_adversarial_and_budget_gates() -> None:
    report = QualificationGate(OcsfCatalog.load_packaged()).qualify(rfc5424_firewall_pack())
    names = {check.name for check in report.checks}

    assert report.passed
    assert report.verify()
    assert {"ocsf-contract", "adversarial:embedded-nul", "adversarial:oversized"} <= names
    assert "resource-budget" in names
    assert not report.model_copy(update={"passed": False}).verify()


@pytest.mark.asyncio
async def test_control_plane_enforces_human_review_before_signed_activation() -> None:
    control, registry, reviewer = _control_plane()
    proposal = control.submit(pack=rfc5424_firewall_pack(), proposed_by="copilot")
    with pytest.raises(ValueError, match="human-approved"):
        control.qualify(proposal_id=proposal.proposal_id, actor_id="qualifier")

    reviewed = control.review(
        proposal_id=proposal.proposal_id,
        reviewer_id="reviewer-7",
        reviewer_signer=reviewer,
        decision=ReviewDecision.APPROVE,
        reason="captures and OCSF mappings independently verified",
    )
    assert reviewed.status is ProposalStatus.APPROVED
    qualified = control.qualify(proposal_id=proposal.proposal_id, actor_id="qualifier")
    assert qualified.status is ProposalStatus.QUALIFIED
    active = await control.activate(proposal_id=proposal.proposal_id, actor_id="release-bot")

    assert active.status is ProposalStatus.ACTIVE
    assert registry.active_pack(proposal.pack.source_key) == proposal.pack
    assert registry.verify_history()
    assert control.audit_log.verify()


def test_control_plane_forbids_self_approval() -> None:
    control, _, reviewer = _control_plane()
    proposal = control.submit(pack=rfc5424_firewall_pack(), proposed_by="reviewer-7")
    with pytest.raises(ValueError, match="self-approval"):
        control.review(
            proposal_id=proposal.proposal_id,
            reviewer_id="reviewer-7",
            reviewer_signer=reviewer,
            decision=ReviewDecision.APPROVE,
            reason="I authored this",
        )


def test_audit_chain_detects_mutation() -> None:
    log = AppendOnlyAuditLog()
    entry = log.append(
        event_type="parser.proposed",
        actor_id="copilot",
        artifact_sha256="a" * 64,
    )
    assert log.verify()
    log._entries[0] = entry.model_copy(update={"actor_id": "intruder"})
    assert not log.verify()
