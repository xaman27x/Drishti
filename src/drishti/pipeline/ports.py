from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from drishti.domain.events import RawEvent


@dataclass(frozen=True, slots=True)
class ArchiveResult:
    created: bool
    raw_sha256: str


class RawEvidenceStore(Protocol):
    async def put_if_absent(self, event: RawEvent) -> ArchiveResult:
        """Persist exact bytes immutably and return whether a record was created."""
        ...

    async def get(self, event_id: UUID) -> RawEvent | None: ...


class EventPublisher(Protocol):
    async def publish_raw_archived(self, event: RawEvent) -> None:
        """Publish only after the raw evidence store has acknowledged persistence."""
        ...
