from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from drishti.governance.audit import AppendOnlyAuditLog
from drishti.governance.crypto import ArtifactSigner, SignedSourceDefinitionPack, sha256_json
from drishti.governance.qualification import QualificationGate, QualificationReport
from drishti.governance.registry import (
    ParserRegistry,
    RegistryRelease,
    ReviewDecision,
    SignedReview,
)
from drishti.parsers.models import SourceDefinitionPack
from drishti.trust.shadow import ShadowPromotionGate, ShadowReport


class ProposalStatus(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    QUALIFIED = "qualified"
    FAILED = "failed"
    ACTIVE = "active"


class ParserProposal(BaseModel):
    model_config = ConfigDict(frozen=True)

    proposal_id: str
    proposed_by: str
    proposed_at: datetime
    pack: SourceDefinitionPack
    status: ProposalStatus
    review: SignedReview | None = None
    qualification: QualificationReport | None = None
    release_revision: int | None = None


class ParserControlPlane:
    """Enforces separation of duties and the parser lifecycle state machine."""

    def __init__(
        self,
        *,
        registry: ParserRegistry,
        qualification_gate: QualificationGate,
        parser_signer: ArtifactSigner,
        audit_log: AppendOnlyAuditLog | None = None,
        promotion_gate: ShadowPromotionGate | None = None,
    ) -> None:
        self._registry = registry
        self._gate = qualification_gate
        self._parser_signer = parser_signer
        self._promotion_gate = promotion_gate or ShadowPromotionGate()
        self.audit_log = audit_log or AppendOnlyAuditLog()
        self._proposals: dict[str, ParserProposal] = {}

    def submit(self, *, pack: SourceDefinitionPack, proposed_by: str) -> ParserProposal:
        proposal = ParserProposal(
            proposal_id=str(uuid4()),
            proposed_by=proposed_by,
            proposed_at=datetime.now(UTC),
            pack=pack,
            status=ProposalStatus.PROPOSED,
        )
        self._proposals[proposal.proposal_id] = proposal
        self.audit_log.append(
            event_type="parser.proposed",
            actor_id=proposed_by,
            artifact_sha256=pack.sha256(),
            details={"proposal_id": proposal.proposal_id, "source_key": pack.source_key},
        )
        return proposal

    def review(
        self,
        *,
        proposal_id: str,
        reviewer_id: str,
        reviewer_signer: ArtifactSigner,
        decision: ReviewDecision,
        reason: str,
    ) -> ParserProposal:
        proposal = self.get(proposal_id)
        if proposal.status is not ProposalStatus.PROPOSED:
            raise ValueError("only proposed parser packs can be reviewed")
        if reviewer_id == proposal.proposed_by:
            raise ValueError("separation of duties forbids self-approval")
        if reviewer_signer.key_id != reviewer_id:
            raise ValueError("reviewer identity must match the signing key")
        reviewed_at = datetime.now(UTC)
        decision_document = {
            "proposal_id": proposal.proposal_id,
            "pack_sha256": proposal.pack.sha256(),
            "reviewer_id": reviewer_id,
            "decision": decision.value,
            "reason": reason,
            "reviewed_at": reviewed_at.isoformat(),
        }
        review = SignedReview(
            proposal_id=proposal.proposal_id,
            pack_sha256=proposal.pack.sha256(),
            reviewer_id=reviewer_id,
            decision=decision,
            reason=reason,
            reviewed_at=reviewed_at,
            signature=reviewer_signer.sign_digest(
                sha256_json(decision_document), purpose="drishti.human-review/v1"
            ),
        )
        status = (
            ProposalStatus.APPROVED
            if decision is ReviewDecision.APPROVE
            else ProposalStatus.REJECTED
        )
        updated = proposal.model_copy(update={"status": status, "review": review})
        self._proposals[proposal_id] = updated
        self.audit_log.append(
            event_type=f"parser.{status.value}",
            actor_id=reviewer_id,
            artifact_sha256=proposal.pack.sha256(),
            details={"proposal_id": proposal_id, "reason": reason},
        )
        return updated

    def qualify(self, *, proposal_id: str, actor_id: str) -> ParserProposal:
        proposal = self.get(proposal_id)
        if proposal.status is not ProposalStatus.APPROVED:
            raise ValueError("only human-approved parser packs may enter qualification")
        report = self._gate.qualify(proposal.pack)
        status = ProposalStatus.QUALIFIED if report.passed else ProposalStatus.FAILED
        updated = proposal.model_copy(update={"status": status, "qualification": report})
        self._proposals[proposal_id] = updated
        self.audit_log.append(
            event_type=f"parser.{status.value}",
            actor_id=actor_id,
            artifact_sha256=proposal.pack.sha256(),
            details={
                "proposal_id": proposal_id,
                "qualification_sha256": report.report_sha256,
            },
        )
        return updated

    async def activate(
        self,
        *,
        proposal_id: str,
        actor_id: str,
        shadow_report: ShadowReport | None = None,
    ) -> ParserProposal:
        proposal = self.get(proposal_id)
        if (
            proposal.status is not ProposalStatus.QUALIFIED
            or proposal.review is None
            or proposal.qualification is None
        ):
            raise ValueError("only qualified, human-approved parser packs may be activated")
        current = self._registry.active_release(proposal.pack.source_key)
        shadow_report_sha256: str | None = None
        if current is not None:
            if shadow_report is None:
                raise ValueError("parser upgrades require counterfactual shadow evidence")
            if (
                shadow_report.active_pack_sha256 != current.signed_pack.pack.sha256()
                or shadow_report.candidate_pack_sha256 != proposal.pack.sha256()
            ):
                raise ValueError("shadow evidence does not match the active and candidate packs")
            promotion = self._promotion_gate.decide(shadow_report)
            if not promotion.accepted:
                raise ValueError("shadow promotion rejected: " + "; ".join(promotion.reasons))
            shadow_report_sha256 = shadow_report.report_sha256
            self.audit_log.append(
                event_type="parser.shadow-qualified",
                actor_id=actor_id,
                artifact_sha256=proposal.pack.sha256(),
                details={
                    "proposal_id": proposal_id,
                    "shadow_report_sha256": shadow_report_sha256,
                    "evaluated_events": shadow_report.total_events,
                },
            )
        signed_pack = SignedSourceDefinitionPack.issue(proposal.pack, signer=self._parser_signer)
        release: RegistryRelease = await self._registry.activate(
            signed_pack=signed_pack,
            qualification=proposal.qualification,
            approval=proposal.review,
            activated_by=actor_id,
            shadow_report_sha256=shadow_report_sha256,
        )
        updated = proposal.model_copy(
            update={
                "status": ProposalStatus.ACTIVE,
                "release_revision": release.registry_revision,
            }
        )
        self._proposals[proposal_id] = updated
        self.audit_log.append(
            event_type="parser.activated",
            actor_id=actor_id,
            artifact_sha256=proposal.pack.sha256(),
            details={
                "proposal_id": proposal_id,
                "registry_revision": release.registry_revision,
                "shadow_report_sha256": shadow_report_sha256,
            },
        )
        return updated

    def get(self, proposal_id: str) -> ParserProposal:
        try:
            return self._proposals[proposal_id]
        except KeyError as exc:
            raise KeyError(f"proposal {proposal_id!r} does not exist") from exc
