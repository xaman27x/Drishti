from __future__ import annotations

import asyncio
import base64
import io
import json
from typing import Any
from uuid import UUID

from drishti.domain.events import RawEvent
from drishti.pipeline.ports import ArchiveResult


class MinioEvidenceStore:
    """S3-compatible raw evidence store using content verification on every read.

    Enable bucket versioning and object lock in production. The adapter uses a
    process lock for local concurrency; production ingress must additionally
    enforce event-ID uniqueness through its durable queue/consumer partition.
    """

    def __init__(self, client: Any, *, bucket: str) -> None:
        self._client = client
        self._bucket = bucket
        self._lock = asyncio.Lock()

    async def ensure_bucket(self) -> None:
        exists = await asyncio.to_thread(self._client.bucket_exists, self._bucket)
        if not exists:
            await asyncio.to_thread(self._client.make_bucket, self._bucket, object_lock=True)

    async def put_if_absent(self, event: RawEvent) -> ArchiveResult:
        object_name = self._object_name(event.event_id)
        async with self._lock:
            existing = await self._stat_or_none(object_name)
            if existing is not None:
                digest = self._metadata(existing).get("raw-sha256", "")
                return ArchiveResult(created=False, raw_sha256=digest)
            envelope = event.model_dump(mode="json", exclude={"raw_bytes", "raw_sha256"})
            encoded = base64.urlsafe_b64encode(
                json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
            ).decode()
            await asyncio.to_thread(
                self._client.put_object,
                self._bucket,
                object_name,
                io.BytesIO(event.raw_bytes),
                len(event.raw_bytes),
                content_type="application/octet-stream",
                metadata={"raw-sha256": event.raw_sha256, "event-envelope": encoded},
            )
            return ArchiveResult(created=True, raw_sha256=event.raw_sha256)

    async def get(self, event_id: UUID) -> RawEvent | None:
        object_name = self._object_name(event_id)
        stat = await self._stat_or_none(object_name)
        if stat is None:
            return None
        response = await asyncio.to_thread(self._client.get_object, self._bucket, object_name)
        try:
            raw_bytes = await asyncio.to_thread(response.read)
        finally:
            response.close()
            response.release_conn()
        metadata = self._metadata(stat)
        encoded = metadata.get("event-envelope")
        if encoded is None:
            raise ValueError("evidence object is missing its event envelope")
        envelope = json.loads(base64.urlsafe_b64decode(encoded.encode()))
        event = RawEvent.model_validate(
            {**envelope, "raw_bytes": raw_bytes, "raw_sha256": metadata.get("raw-sha256")}
        )
        if not event.verify_integrity():
            raise ValueError("evidence object failed SHA-256 verification")
        return event

    async def _stat_or_none(self, object_name: str) -> Any | None:
        try:
            return await asyncio.to_thread(self._client.stat_object, self._bucket, object_name)
        except Exception as exc:
            # minio.error.S3Error is imported lazily so the core package remains portable.
            if getattr(exc, "code", None) in {"NoSuchKey", "NoSuchObject", "NotFound"}:
                return None
            raise

    @staticmethod
    def _metadata(stat: Any) -> dict[str, str]:
        return {
            key.removeprefix("x-amz-meta-").lower(): value
            for key, value in dict(getattr(stat, "metadata", {})).items()
        }

    @staticmethod
    def _object_name(event_id: UUID) -> str:
        return f"raw/by-id/{event_id}.bin"
