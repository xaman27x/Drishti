from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field

from drishti.parsers.models import SourceDefinitionPack


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class SignatureEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True)

    algorithm: str = "Ed25519"
    key_id: str = Field(min_length=1, max_length=128)
    purpose: str = Field(min_length=1, max_length=128)
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    signed_at: datetime
    signature_base64: str

    def material(self) -> bytes:
        return canonical_json(
            {
                "algorithm": self.algorithm,
                "artifact_sha256": self.artifact_sha256,
                "key_id": self.key_id,
                "purpose": self.purpose,
                "signed_at": self.signed_at.isoformat(),
            }
        )


class ArtifactSigner:
    def __init__(self, key_id: str, private_key: Ed25519PrivateKey) -> None:
        self.key_id = key_id
        self._private_key = private_key

    @classmethod
    def generate(cls, key_id: str) -> ArtifactSigner:
        return cls(key_id, Ed25519PrivateKey.generate())

    @classmethod
    def from_base64(cls, key_id: str, private_key_base64: str) -> ArtifactSigner:
        raw = base64.b64decode(private_key_base64, validate=True)
        return cls(key_id, Ed25519PrivateKey.from_private_bytes(raw))

    def private_key_base64(self) -> str:
        raw = self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return base64.b64encode(raw).decode()

    def public_key_base64(self) -> str:
        raw = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode()

    def sign_digest(self, artifact_sha256: str, *, purpose: str) -> SignatureEnvelope:
        unsigned = SignatureEnvelope(
            key_id=self.key_id,
            purpose=purpose,
            artifact_sha256=artifact_sha256,
            signed_at=datetime.now(UTC),
            signature_base64="pending",
        )
        signature = self._private_key.sign(unsigned.material())
        return unsigned.model_copy(
            update={"signature_base64": base64.b64encode(signature).decode()}
        )


class PublicKeyRing:
    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}

    def add_base64(self, key_id: str, public_key_base64: str) -> None:
        raw = base64.b64decode(public_key_base64, validate=True)
        self._keys[key_id] = Ed25519PublicKey.from_public_bytes(raw)

    def verify(self, envelope: SignatureEnvelope, *, purpose: str) -> bool:
        if envelope.algorithm != "Ed25519" or envelope.purpose != purpose:
            return False
        public_key = self._keys.get(envelope.key_id)
        if public_key is None:
            return False
        try:
            signature = base64.b64decode(envelope.signature_base64, validate=True)
            public_key.verify(signature, envelope.material())
        except (InvalidSignature, ValueError):
            return False
        return True


class SignedSourceDefinitionPack(BaseModel):
    model_config = ConfigDict(frozen=True)

    pack: SourceDefinitionPack
    signature: SignatureEnvelope

    @classmethod
    def issue(
        cls, pack: SourceDefinitionPack, *, signer: ArtifactSigner
    ) -> SignedSourceDefinitionPack:
        return cls(
            pack=pack,
            signature=signer.sign_digest(pack.sha256(), purpose="drishti.parser-pack/v1"),
        )

    def verify(self, keyring: PublicKeyRing) -> bool:
        return self.signature.artifact_sha256 == self.pack.sha256() and keyring.verify(
            self.signature, purpose="drishti.parser-pack/v1"
        )


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()
