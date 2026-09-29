from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from importlib import import_module
from typing import Any

from drishti.config import get_settings
from drishti.replay.models import ReplayManifest
from drishti.runtime.governance import keyring
from drishti.runtime.service import Runtime

logger = logging.getLogger(__name__)


def heartbeat(runtime: Runtime, status: str, **details: Any) -> None:
    runtime.state.set("worker", {"at": datetime.now(UTC).isoformat(), "status": status, **details})


async def process_replays(runtime: Runtime) -> None:
    for job in runtime.state.replays():
        if job["status"] not in {"approved", "running"}:
            continue
        manifest = ReplayManifest.model_validate(job["manifest"])
        if not manifest.verify(keyring(runtime.governance.signers["replay-approver"])):
            raise ValueError("replay signature invalid")
        runtime.governance.reload()
        release = runtime.governance.registry.release_at(manifest.registry_revision)
        if (
            release.signed_pack.pack.sha256() != manifest.pack_sha256
            or release.signed_pack.pack.source_key != manifest.source_key
        ):
            raise ValueError("replay parser pin mismatch")
        job["status"] = "running"
        runtime.state.save_replay(job["id"], job)
        outputs: list[dict[str, Any]] = []
        for event_id in manifest.event_ids:
            if not runtime.state.event(event_id):
                outputs.append({"event_id": str(event_id), "status": "missing"})
                continue
            result = await runtime.processor.process(
                event_id, revision=manifest.normalization_revision, release=release
            )
            outputs.append(
                {
                    "event_id": str(event_id),
                    "status": result["status"],
                    "revision": manifest.normalization_revision,
                }
            )
            heartbeat(runtime, "running", current_job="replay " + job["id"], kafka_connected=True)
        job.update(status="completed", results=outputs, completed_at=datetime.now(UTC).isoformat())
        runtime.state.save_replay(job["id"], job)


async def handle_record(runtime: Runtime, consumer: Any, record: Any, topic_partition: Any) -> None:
    key = f"{record.topic}:{record.partition}:{record.offset}"
    await runtime.processor.handle_message(record.value, key)
    # Explicit partition commit; never commit offsets of other fetched records.
    await consumer.commit({topic_partition: record.offset + 1})


async def run() -> None:
    settings = get_settings()
    if settings.adapter_mode != "durable":
        raise ValueError("The separate worker requires DRISHTI_ADAPTER_MODE=durable")
    runtime = Runtime(settings)
    await runtime.initialize_storage()
    consumer = import_module("aiokafka").AIOKafkaConsumer(
        settings.kafka_archived_topic,
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=settings.kafka_consumer_group,
        enable_auto_commit=False,
        auto_offset_reset="earliest",
        max_poll_records=1,
    )
    try:
        await consumer.start()
        while True:
            command = runtime.state.get("worker-command", "running")
            if command == "paused":
                assigned = consumer.assignment()
                if assigned:
                    consumer.pause(*assigned)
                buffered = await consumer.getmany(timeout_ms=1000, max_records=1)
                # A rebalance can assign a partition while paused. Rewind any
                # fetched records so resume cannot silently skip them.
                for partition, records in buffered.items():
                    if records:
                        consumer.seek(partition, records[0].offset)
                heartbeat(runtime, "paused", kafka_connected=True, current_job="Paused by operator")
                continue
            assigned = consumer.assignment()
            if assigned:
                consumer.resume(*assigned)
            heartbeat(
                runtime, "running", kafka_connected=True, current_job="Waiting for archived events"
            )
            batches = await consumer.getmany(timeout_ms=1000, max_records=1)
            for partition, records in batches.items():
                for record in records:
                    heartbeat(
                        runtime,
                        "running",
                        kafka_connected=True,
                        current_job=f"{record.topic}:{record.partition}:{record.offset}",
                    )
                    await handle_record(runtime, consumer, record, partition)
            await process_replays(runtime)
    except Exception as exc:
        heartbeat(runtime, "failed", kafka_connected=False, error=f"{type(exc).__name__}: {exc}")
        logger.exception("Worker failed; uncommitted record will retry after restart")
        raise
    finally:
        await consumer.stop()
        await runtime.close()


if __name__ == "__main__":
    logging.basicConfig(level=get_settings().log_level)
    asyncio.run(run())
