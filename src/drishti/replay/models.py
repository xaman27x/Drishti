from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from drishti.governance.crypto import ArtifactSigner, PublicKeyRing, SignatureEnvelope, sha256_json


class ReplayManifest(BaseModel):
    """Signed capability to replay a bounded set against one exact parser release."""

    model_config = ConfigDict(frozen=True)

    replay_id: UUID
    source_key: str
    registry_revision: int = Field(ge=1)
    pack_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=100_000)
    normalization_revision: int = Field(ge=2)
    reason: str = Field(min_length=8, max_length=1_024)
    requested_by: str
    approved_by: str
    approved_at: datetime
    approval_signature: SignatureEnvelope

    @model_validator(mode="after")
    def separation_of_duties(self) -> ReplayManifest:
        if self.requested_by == self.approved_by:
            raise ValueError("replay requester and approver must be different people")
        if len(self.event_ids) != len(set(self.event_ids)):
            raise ValueError("replay event IDs must be unique")
        return self

    def approval_document(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"approval_signature"})

    @classmethod
    def issue(
        cls,
        *,
        source_key: str,
        registry_revision: int,
        pack_sha256: str,
        event_ids: tuple[UUID, ...],
        normalization_revision: int,
        reason: str,
        requested_by: str,
        approved_by: str,
        approver_signer: ArtifactSigner,
    ) -> ReplayManifest:
        if approver_signer.key_id != approved_by:
            raise ValueError("approver identity must match the signing key")
        replay_id = uuid4()
        approved_at = datetime.now(UTC)
        provisional = cls(
            replay_id=replay_id,
            source_key=source_key,
            registry_revision=registry_revision,
            pack_sha256=pack_sha256,
            event_ids=event_ids,
            normalization_revision=normalization_revision,
            reason=reason,
            requested_by=requested_by,
            approved_by=approved_by,
            approved_at=approved_at,
            approval_signature=approver_signer.sign_digest(
                "0" * 64, purpose="drishti.controlled-replay/v1"
            ),
        )
        return provisional.model_copy(
            update={
                "approval_signature": approver_signer.sign_digest(
                    sha256_json(provisional.approval_document()),
                    purpose="drishti.controlled-replay/v1",
                )
            }
        )

    def verify(self, keyring: PublicKeyRing) -> bool:
        return (
            self.approval_signature.key_id == self.approved_by
            and self.approval_signature.artifact_sha256 == sha256_json(self.approval_document())
            and keyring.verify(self.approval_signature, purpose="drishti.controlled-replay/v1")
        )


class ReplayEventStatus(StrEnum):
    NORMALIZED = "normalized"
    MISSING = "missing"
    REJECTED = "rejected"


class ReplayEventResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: UUID
    status: ReplayEventStatus
    normalized_event_id: UUID | None = None
    detail: str | None = None


class ReplayResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    replay_id: UUID
    started_at: datetime
    completed_at: datetime
    results: tuple[ReplayEventResult, ...]
    result_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
