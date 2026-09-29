from __future__ import annotations

import asyncio
import io
import json
from typing import Any, Protocol


class Artifacts(Protocol):
    async def get(self, key: str) -> dict[str, Any] | None: ...
    async def put(self, key: str, value: dict[str, Any]) -> dict[str, Any]: ...


class MemoryArtifacts:
    def __init__(self) -> None:
        self.documents: dict[str, dict[str, Any]] = {}

    async def get(self, key: str) -> dict[str, Any] | None:
        return self.documents.get(key)

    async def put(self, key: str, value: dict[str, Any]) -> dict[str, Any]:
        return self.documents.setdefault(key, value)


class MinioArtifacts:
    """Single-worker result objects. Existing revisions are never replaced."""

    def __init__(self, client: Any, bucket: str) -> None:
        self.client = client
        self.bucket = bucket

    async def ensure_bucket(self) -> None:
        if not await asyncio.to_thread(self.client.bucket_exists, self.bucket):
            await asyncio.to_thread(self.client.make_bucket, self.bucket)

    async def get(self, key: str) -> dict[str, Any] | None:
        try:
            response = await asyncio.to_thread(self.client.get_object, self.bucket, key)
        except Exception as exc:
            if getattr(exc, "code", None) in {"NoSuchKey", "NoSuchObject", "NotFound"}:
                return None
            raise
        try:
            return json.loads(await asyncio.to_thread(response.read))  # type: ignore[no-any-return]
        finally:
            response.close()
            response.release_conn()

    async def put(self, key: str, value: dict[str, Any]) -> dict[str, Any]:
        existing = await self.get(key)
        if existing is not None:
            return existing
        payload = json.dumps(value, sort_keys=True).encode()
        await asyncio.to_thread(
            self.client.put_object,
            self.bucket,
            key,
            io.BytesIO(payload),
            len(payload),
            content_type="application/json",
        )
        return value
