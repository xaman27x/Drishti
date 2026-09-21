from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from drishti.governance.crypto import (
    ArtifactSigner,
    PublicKeyRing,
    SignatureEnvelope,
    sha256_json,
)
from drishti.trust.dialect import FEATURE_NAMES, DialectFingerprinter


class CapsuleFingerprintBin(BaseModel):
    model_config = ConfigDict(frozen=True)

    fingerprint_hmac: str = Field(pattern=r"^[a-f0-9]{64}$")
    event_count: int = Field(ge=1)


class DialectCapsule(BaseModel):
    """Signed, k-anonymous structural intelligence with no raw log content."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    capsule_id: UUID
    capsule_version: str = "drishti.dialect-capsule/v1"
    site_pseudonym: str = Field(min_length=8, max_length=128)
    source_family: str = Field(min_length=1, max_length=128)
    window_start: datetime
    window_end: datetime
    event_count: int = Field(ge=1)
    k_anonymity: int = Field(ge=2)
    suppressed_events: int = Field(ge=0)
    feature_centroid: tuple[float, ...] = Field(
        min_length=len(FEATURE_NAMES), max_length=len(FEATURE_NAMES)
    )
    fingerprint_bins: tuple[CapsuleFingerprintBin, ...]
    signer_key_id: str
    signature: SignatureEnvelope

    @model_validator(mode="after")
    def validate_capsule(self) -> DialectCapsule:
        if self.window_start.tzinfo is None or self.window_end.tzinfo is None:
            raise ValueError("capsule windows must be timezone-aware")
        if self.window_end <= self.window_start:
            raise ValueError("capsule window end must follow its start")
        represented = sum(item.event_count for item in self.fingerprint_bins)
        if represented + self.suppressed_events != self.event_count:
            raise ValueError("capsule event accounting is inconsistent")
        if any(item.event_count < self.k_anonymity for item in self.fingerprint_bins):
            raise ValueError("capsule contains a fingerprint below its k-anonymity threshold")
        return self

    def capsule_document(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})

    def verify(self, keyring: PublicKeyRing) -> bool:
        return (
            self.signature.key_id == self.signer_key_id
            and self.signature.artifact_sha256 == sha256_json(self.capsule_document())
            and keyring.verify(self.signature, purpose="drishti.dialect-capsule/v1")
        )


class DialectCapsuleBuilder:
    def __init__(
        self,
        *,
        fingerprinter: DialectFingerprinter,
        signer: ArtifactSigner,
        k_anonymity: int = 8,
    ) -> None:
        if k_anonymity < 2:
            raise ValueError("federation capsules require k-anonymity of at least 2")
        self._fingerprinter = fingerprinter
        self._signer = signer
        self._k = k_anonymity

    def build(
        self,
        *,
        site_pseudonym: str,
        source_family: str,
        window_start: datetime,
        window_end: datetime,
        samples: list[bytes],
    ) -> DialectCapsule:
        if len(samples) < self._k:
            raise ValueError("not enough events to satisfy capsule k-anonymity")
        fingerprints = [
            self._fingerprinter.fingerprint(source_key=source_family, raw=sample)
            for sample in samples
        ]
        counts = Counter(item.fingerprint_hmac for item in fingerprints)
        bins = tuple(
            CapsuleFingerprintBin(fingerprint_hmac=digest, event_count=count)
            for digest, count in sorted(counts.items())
            if count >= self._k
        )
        represented = sum(item.event_count for item in bins)
        centroid = tuple(
            round(
                sum(item.features[index] for item in fingerprints) / len(fingerprints),
                2,
            )
            for index in range(len(FEATURE_NAMES))
        )
        provisional = DialectCapsule(
            capsule_id=uuid4(),
            site_pseudonym=site_pseudonym,
            source_family=source_family,
            window_start=window_start,
            window_end=window_end,
            event_count=len(samples),
            k_anonymity=self._k,
            suppressed_events=len(samples) - represented,
            feature_centroid=centroid,
            fingerprint_bins=bins,
            signer_key_id=self._signer.key_id,
            signature=self._signer.sign_digest("0" * 64, purpose="drishti.dialect-capsule/v1"),
        )
        return provisional.model_copy(
            update={
                "signature": self._signer.sign_digest(
                    sha256_json(provisional.capsule_document()),
                    purpose="drishti.dialect-capsule/v1",
                )
            }
        )


class FederatedInsight(BaseModel):
    model_config = ConfigDict(frozen=True)

    capsule_id: UUID
    closest_capsule_id: UUID | None
    structural_similarity: float = Field(ge=0, le=1)
    novel_dialect: bool
    participating_sites: int = Field(ge=1)


class FederationAggregator:
    """Correlates signed capsules without receiving source log payloads."""

    def __init__(self, trusted_sites: PublicKeyRing, *, novelty_threshold: float = 0.5) -> None:
        if not 0 < novelty_threshold <= 1:
            raise ValueError("novelty threshold must be between zero and one")
        self._trusted_sites = trusted_sites
        self._novelty_threshold = novelty_threshold
        self._capsules: dict[UUID, DialectCapsule] = {}

    def ingest(self, capsule: DialectCapsule) -> FederatedInsight:
        if not capsule.verify(self._trusted_sites):
            raise ValueError("capsule signature is invalid or its site is untrusted")
        if capsule.capsule_id in self._capsules:
            raise ValueError("capsule has already been ingested")
        candidates = [
            item for item in self._capsules.values() if item.source_family == capsule.source_family
        ]
        closest: DialectCapsule | None = None
        similarity = 0.0
        for candidate in candidates:
            score = self._weighted_jaccard(capsule, candidate)
            if closest is None or score > similarity:
                closest = candidate
                similarity = score
        self._capsules[capsule.capsule_id] = capsule
        sites = {
            item.site_pseudonym
            for item in self._capsules.values()
            if item.source_family == capsule.source_family
        }
        return FederatedInsight(
            capsule_id=capsule.capsule_id,
            closest_capsule_id=None if closest is None else closest.capsule_id,
            structural_similarity=round(similarity, 6),
            novel_dialect=closest is None or similarity < self._novelty_threshold,
            participating_sites=len(sites),
        )

    @staticmethod
    def _weighted_jaccard(left: DialectCapsule, right: DialectCapsule) -> float:
        left_counts = {item.fingerprint_hmac: item.event_count for item in left.fingerprint_bins}
        right_counts = {item.fingerprint_hmac: item.event_count for item in right.fingerprint_bins}
        keys = set(left_counts) | set(right_counts)
        denominator = sum(max(left_counts.get(key, 0), right_counts.get(key, 0)) for key in keys)
        if denominator == 0:
            return 0.0
        numerator = sum(min(left_counts.get(key, 0), right_counts.get(key, 0)) for key in keys)
        return numerator / denominator
