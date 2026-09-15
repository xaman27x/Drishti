from __future__ import annotations

import json
from typing import Any

from drishti.domain.events import RawEvent


class KafkaArchivedEventPublisher:
    """Publishes an evidence pointer only after MinIO durability is acknowledged."""

    def __init__(self, producer: Any, *, topic: str) -> None:
        self._producer = producer
        self._topic = topic

    async def publish_raw_archived(self, event: RawEvent) -> None:
        envelope = {
            "specversion": "1.0",
            "type": "in.drishti.raw.archived.v1",
            "source": f"drishti://{event.source.tenant_id}/{event.source.source_id}",
            "id": str(event.event_id),
            "time": event.received_at.isoformat(),
            "datacontenttype": "application/json",
            "data": {
                "event_id": str(event.event_id),
                "trace_id": str(event.trace_id),
                "raw_sha256": event.raw_sha256,
                "source": event.source.model_dump(mode="json"),
            },
        }
        await self._producer.send_and_wait(
            self._topic,
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode(),
            key=str(event.event_id).encode(),
            headers=[("content-type", b"application/cloudevents+json")],
        )
