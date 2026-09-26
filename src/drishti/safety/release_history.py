from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from drishti.governance.crypto import (
    ArtifactSigner,
    PublicKeyRing,
    SignatureEnvelope,
    canonical_json,
    sha256_json,
)


def _leaf_hash(payload: bytes) -> str:
    return hashlib.sha256(b"\x00" + payload).hexdigest()


def _node_hash(left: str, right: str) -> str:
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


class ReleaseRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    index: int = Field(ge=0)
    artifact_type: str = Field(min_length=1, max_length=128)
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    metadata: dict[str, Any] = Field(default_factory=dict)
    leaf_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"leaf_hash"})

    def verify(self) -> bool:
        return self.leaf_hash == _leaf_hash(canonical_json(self.payload()))


class ProofSide(StrEnum):
    LEFT = "left"
    RIGHT = "right"


class MerkleProofNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    side: ProofSide
    node_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class InclusionProof(BaseModel):
    model_config = ConfigDict(frozen=True)

    leaf_index: int = Field(ge=0)
    tree_size: int = Field(ge=1)
    root_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    audit_path: tuple[MerkleProofNode, ...]


class SignedHistoryCheckpoint(BaseModel):
    model_config = ConfigDict(frozen=True)

    log_id: str
    tree_size: int = Field(ge=1)
    root_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    issued_at: datetime
    signature: SignatureEnvelope

    def checkpoint_document(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})

    def verify(self, keyring: PublicKeyRing) -> bool:
        return self.signature.artifact_sha256 == sha256_json(
            self.checkpoint_document()
        ) and keyring.verify(self.signature, purpose="drishti.release-history-checkpoint/v1")


class ReleaseHistory:
    """Append-only release history with offline-verifiable inclusion proofs."""

    def __init__(self, *, log_id: str, checkpoint_signer: ArtifactSigner) -> None:
        self.log_id = log_id
        self._signer = checkpoint_signer
        self._leaves: list[ReleaseRecord] = []

    @property
    def leaves(self) -> tuple[ReleaseRecord, ...]:
        return tuple(self._leaves)

    def append(
        self,
        *,
        artifact_type: str,
        artifact_sha256: str,
        metadata: dict[str, Any] | None = None,
    ) -> ReleaseRecord:
        provisional = ReleaseRecord(
            index=len(self._leaves),
            artifact_type=artifact_type,
            artifact_sha256=artifact_sha256,
            metadata=metadata or {},
            leaf_hash="0" * 64,
        )
        leaf = provisional.model_copy(
            update={"leaf_hash": _leaf_hash(canonical_json(provisional.payload()))}
        )
        self._leaves.append(leaf)
        return leaf

    def root_hash(self) -> str:
        if not self._leaves:
            return hashlib.sha256(b"").hexdigest()
        layer = [leaf.leaf_hash for leaf in self._leaves]
        while len(layer) > 1:
            next_layer: list[str] = []
            for index in range(0, len(layer), 2):
                if index + 1 == len(layer):
                    next_layer.append(layer[index])
                else:
                    next_layer.append(_node_hash(layer[index], layer[index + 1]))
            layer = next_layer
        return layer[0]

    def inclusion_proof(self, leaf_index: int) -> InclusionProof:
        if leaf_index < 0 or leaf_index >= len(self._leaves):
            raise IndexError("release record index is outside the history")
        audit_path: list[MerkleProofNode] = []
        layer = [leaf.leaf_hash for leaf in self._leaves]
        cursor = leaf_index
        while len(layer) > 1:
            if cursor % 2 == 1:
                audit_path.append(MerkleProofNode(side=ProofSide.LEFT, node_hash=layer[cursor - 1]))
            elif cursor + 1 < len(layer):
                audit_path.append(
                    MerkleProofNode(side=ProofSide.RIGHT, node_hash=layer[cursor + 1])
                )
            next_layer: list[str] = []
            for index in range(0, len(layer), 2):
                if index + 1 == len(layer):
                    next_layer.append(layer[index])
                else:
                    next_layer.append(_node_hash(layer[index], layer[index + 1]))
            cursor //= 2
            layer = next_layer
        return InclusionProof(
            leaf_index=leaf_index,
            tree_size=len(self._leaves),
            root_hash=layer[0],
            audit_path=tuple(audit_path),
        )

    def checkpoint(self) -> SignedHistoryCheckpoint:
        if not self._leaves:
            raise ValueError("cannot checkpoint an empty release history")
        provisional = SignedHistoryCheckpoint(
            log_id=self.log_id,
            tree_size=len(self._leaves),
            root_hash=self.root_hash(),
            issued_at=datetime.now(UTC),
            signature=self._signer.sign_digest(
                "0" * 64, purpose="drishti.release-history-checkpoint/v1"
            ),
        )
        return provisional.model_copy(
            update={
                "signature": self._signer.sign_digest(
                    sha256_json(provisional.checkpoint_document()),
                    purpose="drishti.release-history-checkpoint/v1",
                )
            }
        )

    @staticmethod
    def verify_inclusion(
        leaf: ReleaseRecord,
        proof: InclusionProof,
        *,
        expected_root: str | None = None,
    ) -> bool:
        if not leaf.verify() or leaf.index != proof.leaf_index:
            return False
        value = leaf.leaf_hash
        for node in proof.audit_path:
            value = (
                _node_hash(node.node_hash, value)
                if node.side is ProofSide.LEFT
                else _node_hash(value, node.node_hash)
            )
        return value == proof.root_hash and (expected_root is None or value == expected_root)
