from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient

from drishti.adapters.memory import InMemoryEventPublisher, InMemoryRawEvidenceStore
from drishti.api.app import create_app
from drishti.config import Settings
from drishti.domain.events import RawEvent, SourceRef
from drishti.parsers.builtin import CEF_FIREWALL_SAMPLE, RFC5424_FIREWALL_SAMPLE
from drishti.runtime.governance import Governance
from drishti.runtime.ingestion import drain_outbox
from drishti.runtime.service import Runtime
from drishti.runtime.state import State
from drishti.runtime.storage import MemoryArtifacts
from drishti.runtime.worker import handle_record, heartbeat, process_replays


@pytest.fixture
async def rt(tmp_path: Path) -> Runtime:
    result = Runtime(
        Settings(
            adapter_mode="memory",
            state_dir=tmp_path,
            demo_admin_enabled=True,
            drift_baseline_size=4,
            drift_window_size=2,
        )
    )
    await result.governance.approve_builtins()
    return result


def request_body(
    raw: bytes = RFC5424_FIREWALL_SAMPLE,
    source: str = "generic.rfc5424-firewall",
    key: str = "test-1",
) -> dict[str, str]:
    return {
        "tenant_id": "test",
        "source_id": "fw-01",
        "source_type": source,
        "payload_base64": base64.b64encode(raw).decode(),
        "idempotency_key": key,
    }


async def ingest(
    rt: Runtime,
    raw: bytes = RFC5424_FIREWALL_SAMPLE,
    source: str = "generic.rfc5424-firewall",
    key: str = "test-1",
) -> UUID:
    receipt = await rt.ingestion.ingest(
        source=SourceRef(tenant_id="test", source_id="fw-01", source_type=source),
        raw_bytes=raw,
        idempotency_key=key,
    )
    return receipt.event_id


@pytest.mark.parametrize(
    ("raw", "source", "expected"),
    [
        (RFC5424_FIREWALL_SAMPLE, "generic.rfc5424-firewall", "normalized"),
        (CEF_FIREWALL_SAMPLE, "generic.cef-firewall", "normalized"),
        (b"unknown", "unregistered", "quarantined"),
        (b"malformed", "generic.rfc5424-firewall", "quarantined"),
    ],
)
async def test_http_ingestion_worker_result_and_raw_round_trip(
    rt: Runtime, raw: bytes, source: str, expected: str
) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=create_app(runtime=rt)), base_url="http://test"
    ) as client:
        response = await client.post("/v1/events", json=request_body(raw, source))
        assert response.status_code == 202
        receipt = response.json()
        event_id = UUID(receipt["event_id"])
        # No inline parser call: receipt returns before a result exists.
        assert rt.state.result(event_id) is None
        assert (await client.get(f"/v1/events/{event_id}/normalized")).status_code == 409
        await drain_outbox(rt.state, rt.evidence, rt.publisher)
        assert isinstance(rt.publisher, InMemoryEventPublisher)
        message = rt.publisher.published[0]
        await rt.processor.handle_message(
            json.dumps(
                {
                    "type": "in.drishti.raw.archived.v1",
                    "data": {"event_id": str(message.event_id), "raw_sha256": message.raw_sha256},
                }
            ).encode(),
            "topic:0:0",
        )
        status = (await client.get(f"/v1/events/{event_id}/status")).json()
        assert status["status"] == expected and status["published"]
        evidence = (await client.get(f"/v1/events/{event_id}/evidence")).json()
        assert base64.b64decode(evidence["payload_base64"]) == raw
        assert evidence["raw_sha256"] == receipt["raw_sha256"] and evidence["integrity_verified"]
        assert (await client.get(f"/v1/events/{event_id}/raw")).content == raw
        normalized = await client.get(f"/v1/events/{event_id}/normalized")
        assert normalized.status_code == (200 if expected == "normalized" else 409)
        if expected == "normalized":
            event = normalized.json()
            assert event["certificate"]["raw_sha256"] == receipt["raw_sha256"]
            assert (
                await client.post("/v1/ocsf/validate", json={"event": event["ocsf_event"]})
            ).json()["valid"]
        again = (await client.post("/v1/events", json=request_body(raw, source))).json()
        assert again["duplicate"] and again["trace_id"] == receipt["trace_id"]
        assert (
            await client.post("/v1/events", json=request_body(raw + b"changed", source))
        ).status_code == 409
        assert len((await client.get("/api/events")).json()) == 1


class FlakyPublisher(InMemoryEventPublisher):
    fail = True

    async def publish_raw_archived(self, event: RawEvent) -> None:
        if self.fail:
            raise ConnectionError("broker unavailable")
        await super().publish_raw_archived(event)


async def test_outbox_recovers_after_process_restart_without_client_retry(rt: Runtime) -> None:
    publisher = FlakyPublisher()
    event_id = await ingest(rt)
    assert await drain_outbox(rt.state, rt.evidence, publisher) == 0
    restarted_state = State(rt.state.path)
    assert len(restarted_state.pending()) == 1
    publisher.fail = False
    assert await drain_outbox(restarted_state, rt.evidence, publisher) == 1
    assert publisher.published[0].event_id == event_id
    assert not restarted_state.pending()


async def test_crash_between_intent_and_archive_is_recovered(rt: Runtime) -> None:
    from uuid import uuid4

    event = RawEvent.create(
        event_id=uuid4(),
        trace_id=uuid4(),
        source=SourceRef(tenant_id="t", source_id="s"),
        raw_bytes=b"recover",
        observed_at=None,
        idempotency_key=None,
    )
    rt.state.stage(event)  # Simulate crash before put_object.
    assert await rt.evidence.get(event.event_id) is None
    await drain_outbox(State(rt.state.path), rt.evidence, rt.publisher)
    assert await rt.evidence.get(event.event_id) == event


async def test_duplicate_delivery_reuses_result_and_drift_state(rt: Runtime) -> None:
    event_id = await ingest(rt)
    first = await rt.processor.process(event_id)
    snapshot = rt.state.get(first["drift_key"])
    second = await rt.processor.process(event_id)
    assert first == second
    assert rt.state.get(first["drift_key"]) == snapshot
    assert rt.state.counts()["normalized"] == 1


async def test_artifact_survives_crash_before_result_index(
    rt: Runtime, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_id = await ingest(rt)
    original = rt.state.save_result

    def crash(*args: Any, **kwargs: Any) -> None:
        raise OSError("crash after object write")

    monkeypatch.setattr(rt.state, "save_result", crash)
    with pytest.raises(OSError):
        await rt.processor.process(event_id)
    assert rt.state.result(event_id) is None
    monkeypatch.setattr(rt.state, "save_result", original)
    result = await rt.processor.process(event_id)
    assert result["status"] == "normalized"
    assert len(rt.state.get(result["drift_key"])["baseline"]) == 1


class FailingArtifacts(MemoryArtifacts):
    async def put(self, key: str, value: dict[str, Any]) -> dict[str, Any]:
        raise ConnectionError("object store offline")


async def test_consumer_does_not_commit_before_persistence(rt: Runtime) -> None:
    event_id = await ingest(rt)
    event = await rt.evidence.get(event_id)
    assert event
    record = SimpleNamespace(
        topic="t",
        partition=0,
        offset=4,
        value=json.dumps(
            {
                "type": "in.drishti.raw.archived.v1",
                "data": {"event_id": str(event_id), "raw_sha256": event.raw_sha256},
            }
        ).encode(),
    )

    class Consumer:
        def __init__(self) -> None:
            self.commits: list[Any] = []

        async def commit(self, offsets: Any) -> None:
            self.commits.append(offsets)

    consumer = Consumer()
    original = rt.processor.artifacts
    rt.processor.artifacts = FailingArtifacts()
    with pytest.raises(ConnectionError):
        await handle_record(rt, consumer, record, ("t", 0))
    assert consumer.commits == []
    rt.processor.artifacts = original
    await handle_record(rt, consumer, record, ("t", 0))
    assert consumer.commits == [{("t", 0): 5}]


async def test_governance_and_results_survive_reload(rt: Runtime) -> None:
    event_id = await ingest(rt)
    result = await rt.processor.process(event_id)
    governance = Governance(State(rt.state.path), rt.catalog, rt.state.path.parent)
    assert governance.registry.verify_history()
    assert len(governance.registry.history) == 2
    assert State(rt.state.path).result(event_id) == result
    saved = rt.state.get("governance")
    saved["document"]["releases"][0]["activated_by"] = "tampered"
    rt.state.set("governance", saved)
    with pytest.raises(ValueError, match="signature"):
        governance.reload()


async def test_unsigned_or_unapproved_parser_never_runs(tmp_path: Path) -> None:
    rt = Runtime(Settings(adapter_mode="memory", state_dir=tmp_path))
    event_id = await ingest(rt)
    assert (await rt.processor.process(event_id))["status"] == "quarantined"


async def test_poison_notification_is_durably_recorded(rt: Runtime) -> None:
    await rt.processor.handle_message(b"not JSON", "topic:0:9")
    assert State(rt.state.path).counts()["deadletters"] == 1


async def test_drift_persists_across_restart_and_quarantines(rt: Runtime) -> None:
    for i in range(4):
        await rt.processor.process(await ingest(rt, key=f"baseline-{i}"))
    from drishti.runtime.processing import Processor

    processor = Processor(
        State(rt.state.path),
        rt.evidence,
        rt.artifacts,
        Governance(rt.state, rt.catalog, rt.state.path.parent),
        rt.settings,
    )
    for i in range(2):
        event_id = await ingest(rt, CEF_FIREWALL_SAMPLE, key=f"changed-{i}")
        result = await processor.process(event_id)
    assert result["status"] == "quarantined"
    assert result["drift"]["status"] == "quarantine"


async def test_replay_requires_separate_approval_and_keeps_original(rt: Runtime) -> None:
    event_id = await ingest(rt)
    original = await rt.processor.process(event_id)
    headers = {"X-Drishti-Demo": "true"}
    async with AsyncClient(
        transport=ASGITransport(app=create_app(runtime=rt)), base_url="http://test"
    ) as client:
        body = {
            "event_ids": [str(event_id)],
            "registry_revision": 1,
            "reason": "verify replay flow",
        }
        assert (await client.post("/api/replay", json=body)).status_code == 403
        job = (await client.post("/api/replay", json=body, headers=headers)).json()
        await process_replays(rt)
        assert rt.state.result(event_id, 2) is None
        approved = await client.post(f"/api/replay/{job['id']}/approve", json={}, headers=headers)
        assert approved.status_code == 200
        await process_replays(rt)
        assert rt.state.result(event_id) == original
        replayed = (await client.get(f"/v1/events/{event_id}/normalized?revision=2")).json()
        assert replayed["certificate"]["raw_sha256"] == original["raw_sha256"]
        assert replayed["normalized_event_id"] != original["normalized"]["normalized_event_id"]
        assert (
            await client.post("/api/replay", json={**body, "registry_revision": 2}, headers=headers)
        ).status_code == 422


async def test_health_reports_missing_stale_and_live_worker(rt: Runtime) -> None:
    assert (await rt.health())["status"] == "degraded"
    heartbeat(rt, "running")
    assert (await rt.health())["status"] == "ready"
    rt.state.set("worker", {"status": "running", "at": "2000-01-01T00:00:00+00:00"})
    assert not (await rt.health())["checks"]["worker"]


async def test_copilot_is_proposal_only_and_upgrade_gate_still_applies(rt: Runtime) -> None:
    event_id = await ingest(rt)
    headers = {"X-Drishti-Demo": "true"}
    async with AsyncClient(
        transport=ASGITransport(app=create_app(runtime=rt)), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/copilot/proposals", json={"event_ids": [str(event_id)]}, headers=headers
        )
        assert response.status_code == 200
        proposal = response.json()["proposal"]
        assert proposal["status"] == "proposed"
        path = f"/api/governance/proposals/{proposal['proposal_id']}"
        assert (
            await client.post(path, json={"action": "activate"}, headers=headers)
        ).status_code == 409
        assert (
            await client.post(path, json={"action": "approve"}, headers=headers)
        ).status_code == 200
        assert (await client.post(path, json={"action": "qualify"}, headers=headers)).json()[
            "status"
        ] == "qualified"
        blocked = await client.post(
            path, json={"action": "activate", "event_ids": [str(event_id)] * 100}, headers=headers
        )
        assert blocked.status_code == 409
        assert "requires 100 events" in blocked.json()["detail"]
        assert len(rt.governance.registry.history) == 2


async def test_original_ingestion_retries_failed_publish_and_preserves_trace() -> None:
    from drishti.pipeline.ingestion import IngestionService

    publisher = FlakyPublisher()
    service = IngestionService(
        evidence_store=InMemoryRawEvidenceStore(), publisher=publisher, max_event_bytes=1024
    )
    source = SourceRef(tenant_id="t", source_id="s")
    with pytest.raises(ConnectionError):
        await service.ingest(source=source, raw_bytes=b"test", idempotency_key="same")
    publisher.fail = False
    receipt = await service.ingest(source=source, raw_bytes=b"test", idempotency_key="same")
    assert receipt.duplicate and len(publisher.published) == 1
    assert receipt.trace_id == publisher.published[0].trace_id
