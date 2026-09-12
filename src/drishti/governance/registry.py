from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from drishti.governance.crypto import (
    ArtifactSigner,
    PublicKeyRing,
    SignatureEnvelope,
    SignedSourceDefinitionPack,
    sha256_json,
)
from drishti.governance.qualification import QualificationReport
from drishti.parsers.models import SourceDefinitionPack


class ReviewDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class SignedReview(BaseModel):
    model_config = ConfigDict(frozen=True)

    proposal_id: str
    pack_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reviewer_id: str
    decision: ReviewDecision
    reason: str
    reviewed_at: datetime
    signature: SignatureEnvelope

    def decision_document(self) -> dict[str, str]:
        return {
            "proposal_id": self.proposal_id,
            "pack_sha256": self.pack_sha256,
            "reviewer_id": self.reviewer_id,
            "decision": self.decision.value,
            "reason": self.reason,
            "reviewed_at": self.reviewed_at.isoformat(),
        }

    def verify(self, keyring: PublicKeyRing) -> bool:
        return (
            self.signature.artifact_sha256 == sha256_json(self.decision_document())
            and self.signature.key_id == self.reviewer_id
            and keyring.verify(self.signature, purpose="drishti.human-review/v1")
        )


class RegistryRelease(BaseModel):
    """Immutable, fully-attested activation record."""

    model_config = ConfigDict(frozen=True)

    registry_revision: int = Field(ge=1)
    signed_pack: SignedSourceDefinitionPack
    qualification: QualificationReport
    approval: SignedReview
    activated_by: str
    activated_at: datetime
    supersedes_revision: int | None = None
    release_signature: SignatureEnvelope

    def release_document(self) -> dict[str, object]:
        return {
            "registry_revision": self.registry_revision,
            "source_key": self.signed_pack.pack.source_key,
            "pack_uid": self.signed_pack.pack.pack_uid,
            "pack_version": self.signed_pack.pack.version,
            "pack_sha256": self.signed_pack.pack.sha256(),
            "pack_signature_sha256": sha256_json(
                self.signed_pack.signature.model_dump(mode="json")
            ),
            "qualification_sha256": self.qualification.report_sha256,
            "approval_sha256": sha256_json(self.approval.model_dump(mode="json")),
            "activated_by": self.activated_by,
            "activated_at": self.activated_at.isoformat(),
            "supersedes_revision": self.supersedes_revision,
        }

    def verify(
        self,
        *,
        parser_keys: PublicKeyRing,
        reviewer_keys: PublicKeyRing,
        registry_keys: PublicKeyRing,
    ) -> bool:
        pack_digest = self.signed_pack.pack.sha256()
        return (
            self.signed_pack.verify(parser_keys)
            and self.qualification.passed
            and self.qualification.verify()
            and self.qualification.pack_sha256 == pack_digest
            and self.approval.decision is ReviewDecision.APPROVE
            and self.approval.pack_sha256 == pack_digest
            and self.approval.verify(reviewer_keys)
            and self.release_signature.artifact_sha256 == sha256_json(self.release_document())
            and registry_keys.verify(self.release_signature, purpose="drishti.registry-release/v1")
        )


class ParserRegistry:
    """Signed registry with atomic activation pointers and immutable history."""

    def __init__(
        self,
        *,
        registry_signer: ArtifactSigner,
        parser_keys: PublicKeyRing,
        reviewer_keys: PublicKeyRing,
    ) -> None:
        self._registry_signer = registry_signer
        self._parser_keys = parser_keys
        self._reviewer_keys = reviewer_keys
        self._registry_keys = PublicKeyRing()
        self._registry_keys.add_base64(registry_signer.key_id, registry_signer.public_key_base64())
        self._history: list[RegistryRelease] = []
        self._active: dict[str, int] = {}
        self._lock = asyncio.Lock()

    @property
    def history(self) -> tuple[RegistryRelease, ...]:
        return tuple(self._history)

    async def activate(
        self,
        *,
        signed_pack: SignedSourceDefinitionPack,
        qualification: QualificationReport,
        approval: SignedReview,
        activated_by: str,
    ) -> RegistryRelease:
        async with self._lock:
            pack = signed_pack.pack
            if not signed_pack.verify(self._parser_keys):
                raise ValueError("parser pack signature is invalid or untrusted")
            if (
                not qualification.passed
                or not qualification.verify()
                or qualification.pack_sha256 != pack.sha256()
            ):
                raise ValueError("a passing qualification report for this exact pack is required")
            if approval.decision is not ReviewDecision.APPROVE or not approval.verify(
                self._reviewer_keys
            ):
                raise ValueError("a valid signed human approval is required")
            if approval.pack_sha256 != pack.sha256():
                raise ValueError("human approval is for a different parser pack")
            current = self.active_release(pack.source_key)
            if current is not None and pack.semver() <= current.signed_pack.pack.semver():
                raise ValueError("activation version must increase monotonically")

            now = datetime.now(UTC)
            revision = len(self._history) + 1
            unsigned = RegistryRelease(
                registry_revision=revision,
                signed_pack=signed_pack,
                qualification=qualification,
                approval=approval,
                activated_by=activated_by,
                activated_at=now,
                supersedes_revision=(None if current is None else current.registry_revision),
                release_signature=self._registry_signer.sign_digest(
                    "0" * 64, purpose="drishti.registry-release/v1"
                ),
            )
            release = unsigned.model_copy(
                update={
                    "release_signature": self._registry_signer.sign_digest(
                        sha256_json(unsigned.release_document()),
                        purpose="drishti.registry-release/v1",
                    )
                }
            )
            if not release.verify(
                parser_keys=self._parser_keys,
                reviewer_keys=self._reviewer_keys,
                registry_keys=self._registry_keys,
            ):
                raise RuntimeError("registry created an unverifiable release")
            self._history.append(release)
            self._active[pack.source_key] = revision
            return release

    def active_release(self, source_key: str) -> RegistryRelease | None:
        revision = self._active.get(source_key)
        return None if revision is None else self._history[revision - 1]

    def active_pack(self, source_key: str) -> SourceDefinitionPack | None:
        release = self.active_release(source_key)
        return None if release is None else release.signed_pack.pack

    def release_at(self, revision: int) -> RegistryRelease:
        if revision < 1 or revision > len(self._history):
            raise KeyError(f"registry revision {revision} does not exist")
        return self._history[revision - 1]

    def verify_history(self) -> bool:
        latest_by_source: dict[str, int] = {}
        for index, release in enumerate(self._history, start=1):
            source_key = release.signed_pack.pack.source_key
            if (
                release.registry_revision != index
                or release.supersedes_revision != latest_by_source.get(source_key)
            ):
                return False
            if not release.verify(
                parser_keys=self._parser_keys,
                reviewer_keys=self._reviewer_keys,
                registry_keys=self._registry_keys,
            ):
                return False
            latest_by_source[source_key] = index
        return latest_by_source == self._active
