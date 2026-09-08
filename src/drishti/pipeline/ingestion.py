from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from drishti.domain.events import RawEvent, SourceRef
from drishti.pipeline.ports import EventPublisher, RawEvidenceStore


class IngestionError(Exception):
    """Base error for rejected ingestion requests."""


class PayloadTooLargeError(IngestionError):
    pass


class IdempotencyConflictError(IngestionError):
    pass


@dataclass(frozen=True, slots=True)
class IngestionReceipt:
    event_id: UUID
    trace_id: UUID
    raw_sha256: str
    duplicate: bool


class IngestionService:
    """Archives raw evidence before making an event visible downstream."""

    def __init__(
        self,
        *,
        evidence_store: RawEvidenceStore,
        publisher: EventPublisher,
        max_event_bytes: int,
    ) -> None:
        self._evidence_store = evidence_store
        self._publisher = publisher
        self._max_event_bytes = max_event_bytes

    async def ingest(
        self,
        *,
        source: SourceRef,
        raw_bytes: bytes,
        idempotency_key: str | None = None,
        observed_at: datetime | None = None,
    ) -> IngestionReceipt:
        if len(raw_bytes) > self._max_event_bytes:
            raise PayloadTooLargeError(
                f"event contains {len(raw_bytes)} bytes; limit is {self._max_event_bytes}"
            )

        event_id = self._event_id(source, idempotency_key)
        event = RawEvent.create(
            event_id=event_id,
            trace_id=uuid4(),
            source=source,
            raw_bytes=raw_bytes,
            idempotency_key=idempotency_key,
            observed_at=observed_at,
        )

        archive_result = await self._evidence_store.put_if_absent(event)
        if not archive_result.created:
            if archive_result.raw_sha256 != event.raw_sha256:
                raise IdempotencyConflictError(
                    "idempotency key was already used for a different payload"
                )
            return IngestionReceipt(
                event_id=event.event_id,
                trace_id=event.trace_id,
                raw_sha256=event.raw_sha256,
                duplicate=True,
            )

        # This ordering is a forensic invariant: publishing cannot precede archival.
        await self._publisher.publish_raw_archived(event)
        return IngestionReceipt(
            event_id=event.event_id,
            trace_id=event.trace_id,
            raw_sha256=event.raw_sha256,
            duplicate=False,
        )

    @staticmethod
    def _event_id(source: SourceRef, idempotency_key: str | None) -> UUID:
        if idempotency_key is None:
            return uuid4()
        stable_name = f"drishti:{source.tenant_id}:{source.source_id}:{idempotency_key}"
        return uuid5(NAMESPACE_URL, stable_name)
