from __future__ import annotations

import asyncio
from uuid import UUID

from drishti.domain.events import RawEvent
from drishti.normalization.models import CertifiedNormalizedEvent
from drishti.pipeline.ports import ArchiveResult


class InMemoryRawEvidenceStore:
    """Concurrency-safe development adapter; not suitable for production evidence."""

    def __init__(self) -> None:
        self._events: dict[UUID, RawEvent] = {}
        self._lock = asyncio.Lock()

    async def put_if_absent(self, event: RawEvent) -> ArchiveResult:
        async with self._lock:
            existing = self._events.get(event.event_id)
            if existing is not None:
                return ArchiveResult(created=False, raw_sha256=existing.raw_sha256)
            self._events[event.event_id] = event
            return ArchiveResult(created=True, raw_sha256=event.raw_sha256)

    async def get(self, event_id: UUID) -> RawEvent | None:
        return self._events.get(event_id)


class InMemoryEventPublisher:
    """Development publisher that records archived-event notifications."""

    def __init__(self) -> None:
        self.published: list[RawEvent] = []

    async def publish_raw_archived(self, event: RawEvent) -> None:
        self.published.append(event)


class InMemoryNormalizedEventSink:
    """Idempotent sink used by tests and the air-gapped demo profile."""

    def __init__(self) -> None:
        self.events: dict[UUID, CertifiedNormalizedEvent] = {}
        self._lock = asyncio.Lock()

    async def put_if_absent(self, event: CertifiedNormalizedEvent) -> bool:
        async with self._lock:
            if event.normalized_event_id in self.events:
                return False
            self.events[event.normalized_event_id] = event
            return True
