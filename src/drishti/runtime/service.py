from __future__ import annotations

import asyncio
import logging
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import Any

from drishti.adapters.kafka import KafkaArchivedEventPublisher
from drishti.adapters.memory import InMemoryEventPublisher, InMemoryRawEvidenceStore
from drishti.adapters.minio import MinioEvidenceStore
from drishti.config import Settings
from drishti.ocsf.catalog import OcsfCatalog
from drishti.pipeline.ports import EventPublisher, RawEvidenceStore
from drishti.runtime.governance import Governance
from drishti.runtime.ingestion import DurableIngestion, drain_outbox
from drishti.runtime.processing import Processor
from drishti.runtime.state import State
from drishti.runtime.storage import Artifacts, MemoryArtifacts, MinioArtifacts

logger = logging.getLogger(__name__)


class ManagedPublisher:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.producer: Any = None

    async def publish_raw_archived(self, event: Any) -> None:
        if self.producer is None:
            producer = import_module("aiokafka").AIOKafkaProducer(
                bootstrap_servers=self.settings.kafka_bootstrap_servers,
                acks="all",
                enable_idempotence=True,
                compression_type="gzip",
                request_timeout_ms=10000,
            )
            try:
                await producer.start()
            except BaseException:
                await producer.stop()
                raise
            self.producer = producer
        try:
            await asyncio.wait_for(
                KafkaArchivedEventPublisher(
                    self.producer, topic=self.settings.kafka_archived_topic
                ).publish_raw_archived(event),
                timeout=15,
            )
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        if self.producer:
            producer, self.producer = self.producer, None
            await producer.stop()


class Runtime:
    def __init__(
        self,
        settings: Settings,
        *,
        state: State | None = None,
        evidence: RawEvidenceStore | None = None,
        artifacts: Artifacts | None = None,
        publisher: EventPublisher | None = None,
    ) -> None:
        self.settings = settings
        self.state = state or State(settings.state_dir / "runtime.sqlite3")
        self.catalog = OcsfCatalog.load_packaged()
        self.governance = Governance(self.state, self.catalog, self.state.path.parent)
        self.client: Any = None
        if settings.adapter_mode == "durable":
            from urllib3 import PoolManager, Timeout

            self.client = import_module("minio").Minio(
                settings.minio_endpoint,
                access_key=settings.minio_access_key,
                secret_key=settings.minio_secret_key.get_secret_value(),
                secure=settings.minio_secure,
                http_client=PoolManager(timeout=Timeout(connect=3, read=10), retries=1),
            )
        self.evidence: RawEvidenceStore = evidence or (
            MinioEvidenceStore(self.client, bucket=settings.minio_bucket)
            if self.client
            else InMemoryRawEvidenceStore()
        )
        self.artifacts: Artifacts = artifacts or (
            MinioArtifacts(self.client, settings.minio_results_bucket)
            if self.client
            else MemoryArtifacts()
        )
        self.publisher: EventPublisher = publisher or (
            ManagedPublisher(settings) if self.client else InMemoryEventPublisher()
        )
        self.ingestion = DurableIngestion(
            self.state, self.evidence, self.publisher, settings.max_event_bytes
        )
        self.processor = Processor(
            self.state, self.evidence, self.artifacts, self.governance, settings
        )
        self.control_lock = asyncio.Lock()
        self.outbox_task: asyncio.Task[None] | None = None

    async def initialize_storage(self) -> None:
        if isinstance(self.evidence, MinioEvidenceStore):
            await self.evidence.ensure_bucket()
        if isinstance(self.artifacts, MinioArtifacts):
            await self.artifacts.ensure_bucket()

    async def run_outbox(self) -> None:
        while True:
            try:
                await drain_outbox(self.state, self.evidence, self.publisher)
            except Exception:
                logger.exception("Outbox iteration failed; durable intents retained")
            await asyncio.sleep(self.settings.outbox_interval_seconds)

    async def start_api(self) -> None:
        await self.initialize_storage()
        self.outbox_task = asyncio.create_task(self.run_outbox())

    async def close(self) -> None:
        if self.outbox_task:
            self.outbox_task.cancel()
            with suppress(asyncio.CancelledError):
                await self.outbox_task
        if isinstance(self.publisher, ManagedPublisher):
            await self.publisher.close()

    async def health(self) -> dict[str, Any]:
        checks: dict[str, bool] = {"state": False, "minio": False, "kafka": False}
        try:
            self.state.counts()
            checks["state"] = True
            if self.client:
                checks["minio"] = bool(
                    await asyncio.to_thread(self.client.bucket_exists, self.settings.minio_bucket)
                ) and bool(
                    await asyncio.to_thread(
                        self.client.bucket_exists, self.settings.minio_results_bucket
                    )
                )
                host, port = self.settings.kafka_bootstrap_servers.split(",")[0].rsplit(":", 1)
                _, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), 2)
                writer.close()
                await writer.wait_closed()
                checks["kafka"] = True
            else:
                checks.update(minio=True, kafka=True)
        except Exception:
            logger.warning("Dependency probe failed", exc_info=True)
        heartbeat = self.state.get("worker", {})
        fresh = False
        if heartbeat.get("at"):
            fresh = (
                datetime.now(UTC) - datetime.fromisoformat(heartbeat["at"])
            ).total_seconds() < self.settings.worker_stale_seconds
        checks["worker"] = fresh and heartbeat.get("status") in {"running", "paused"}
        return {
            "status": "ready" if all(checks.values()) else "degraded",
            "checks": checks,
            "worker": heartbeat,
            "kafka_probe": "TCP reachability; worker heartbeat reports consumer state",
        }


def ephemeral_runtime() -> Runtime:
    directory = Path(tempfile.mkdtemp(prefix="drishti-test-"))
    return Runtime(Settings(adapter_mode="memory", state_dir=directory))
