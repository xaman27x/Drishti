from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from drishti.governance.crypto import canonical_json

GENESIS_HASH = "0" * 64


class AuditEntry(BaseModel):
    """One link in Drishti's tamper-evident governance history."""

    model_config = ConfigDict(frozen=True)

    sequence: int = Field(ge=1)
    event_type: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=128)
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    details: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime
    previous_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    entry_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    def unsigned_document(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"entry_hash"})


class AppendOnlyAuditLog:
    """In-memory reference ledger with cryptographic link verification.

    The storage adapter can later persist the same immutable entries in a WORM
    bucket or verifiable release history without changing governance semantics.
    """

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    def append(
        self,
        *,
        event_type: str,
        actor_id: str,
        artifact_sha256: str,
        details: dict[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> AuditEntry:
        sequence = len(self._entries) + 1
        timestamp = occurred_at or datetime.now(UTC)
        previous_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        detail_values = details or {}
        provisional = AuditEntry(
            sequence=sequence,
            event_type=event_type,
            actor_id=actor_id,
            artifact_sha256=artifact_sha256,
            details=detail_values,
            occurred_at=timestamp,
            previous_hash=previous_hash,
            entry_hash="0" * 64,
        )
        entry = provisional.model_copy(
            update={
                "entry_hash": hashlib.sha256(
                    canonical_json(provisional.unsigned_document())
                ).hexdigest()
            }
        )
        self._entries.append(entry)
        return entry

    def verify(self) -> bool:
        previous = GENESIS_HASH
        for expected_sequence, entry in enumerate(self._entries, start=1):
            if entry.sequence != expected_sequence or entry.previous_hash != previous:
                return False
            digest = hashlib.sha256(canonical_json(entry.unsigned_document())).hexdigest()
            if digest != entry.entry_hash:
                return False
            previous = entry.entry_hash
        return True

    def restore(self, entries: list[AuditEntry]) -> None:
        previous = self._entries
        self._entries = entries
        if not self.verify():
            self._entries = previous
            raise ValueError("persisted audit chain failed verification")
