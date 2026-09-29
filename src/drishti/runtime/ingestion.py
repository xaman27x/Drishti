from __future__ import annotations

from datetime import datetime

from drishti.domain.events import RawEvent, SourceRef
from drishti.pipeline.ingestion import IngestionReceipt, IngestionService, PayloadTooLargeError
from drishti.pipeline.ports import EventPublisher, RawEvidenceStore
from drishti.runtime.state import State


class DurableIngestion(IngestionService):
    """Archives synchronously; a durable outbox publishes asynchronously."""

    def __init__(
        self,
        state: State,
        evidence: RawEvidenceStore,
        publisher: EventPublisher,
        max_event_bytes: int,
    ) -> None:
        super().__init__(
            evidence_store=evidence, publisher=publisher, max_event_bytes=max_event_bytes
        )
        self.state = state
        self.evidence = evidence
        self.limit = max_event_bytes

    async def ingest(
        self,
        *,
        source: SourceRef,
        raw_bytes: bytes,
        idempotency_key: str | None = None,
        observed_at: datetime | None = None,
    ) -> IngestionReceipt:
        from uuid import uuid4

        if len(raw_bytes) > self.limit:
            raise PayloadTooLargeError(
                f"event contains {len(raw_bytes)} bytes; limit is {self.limit}"
            )
        candidate = RawEvent.create(
            event_id=self._event_id(source, idempotency_key),
            trace_id=uuid4(),
            source=source,
            raw_bytes=raw_bytes,
            idempotency_key=idempotency_key,
            observed_at=observed_at,
        )
        event, created = self.state.stage(candidate)
        archived = await self.evidence.put_if_absent(event)
        if archived.raw_sha256 != event.raw_sha256:
            raise ValueError("stored raw evidence does not match ingestion intent")
        self.state.mark_archived(event.event_id)
        return IngestionReceipt(
            event_id=event.event_id,
            trace_id=event.trace_id,
            raw_sha256=event.raw_sha256,
            duplicate=not created,
        )


async def drain_outbox(state: State, evidence: RawEvidenceStore, publisher: EventPublisher) -> int:
    """At-least-once: crash after send may republish; the worker deduplicates."""
    published = 0
    for event in state.pending():
        try:
            result = await evidence.put_if_absent(event)
            if result.raw_sha256 != event.raw_sha256:
                raise ValueError("archive digest mismatch")
            state.mark_archived(event.event_id)
            await publisher.publish_raw_archived(event)
            state.mark_published(event.event_id)
            published += 1
        except Exception as exc:
            state.publication_error(event.event_id, f"{type(exc).__name__}: {exc}")
    return published
