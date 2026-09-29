from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from drishti.governance.registry import ReviewDecision
from drishti.parsers.models import SourceDefinitionPack
from drishti.replay.models import ReplayManifest
from drishti.runtime.service import Runtime
from drishti.runtime.state import decode_event
from drishti.safety.parser_comparison import ParserComparator

router = APIRouter()


def runtime(request: Request) -> Runtime:
    value = getattr(request.app.state, "runtime", None)
    if value is None:
        raise HTTPException(503, "Start the durable Compose runtime for this endpoint")
    return value  # type: ignore[no-any-return]


_runtime_dependency = Depends(runtime)


def operator(request: Request, rt: Runtime = _runtime_dependency) -> None:
    if rt.settings.environment not in {"local", "test"} or not rt.settings.demo_admin_enabled:
        raise HTTPException(403, "Local demo controls are disabled")
    if request.headers.get("x-drishti-demo") != "true":
        raise HTTPException(403, "Explicit X-Drishti-Demo: true header required")


def require_event(rt: Runtime, event_id: UUID) -> dict[str, Any]:
    row = rt.state.event(event_id)
    if row is None:
        raise HTTPException(404, "Event not found")
    return row


def view(rt: Runtime, row: dict[str, Any]) -> dict[str, Any]:
    raw = decode_event(row["document"])
    result = rt.state.result(raw.event_id)
    normalized = result.get("normalized") if result else None
    certificate = normalized["certificate"] if normalized else None
    ocsf = normalized["ocsf_event"] if normalized else None
    status = (
        result["status"].title()
        if result
        else ("Processing" if row["published"] else "Archived" if row["archived"] else "Pending")
    )
    return {
        "id": str(raw.event_id),
        "timestamp": raw.received_at.isoformat(),
        "source": raw.source.source_id,
        "sourceType": raw.source.source_type,
        "tenantId": raw.source.tenant_id,
        "format": "RFC5424"
        if "rfc5424" in raw.source.source_type
        else "CEF"
        if "cef" in raw.source.source_type
        else "Unknown",
        "parser": result.get("parser", "—") if result else "—",
        "status": status,
        "severity": str(ocsf.get("severity_id", "—")) if ocsf else "—",
        "className": "Network Activity" if ocsf else "—",
        "duration": f"{result['duration_ms']} ms" if result else "—",
        "raw": raw.raw_bytes.decode("utf-8", errors="replace"),
        "rawSha256": raw.raw_sha256,
        "traceId": str(raw.trace_id),
        "normalized": ocsf,
        "certificate": certificate,
        "result": result,
        "size": f"{len(raw.raw_bytes)} B",
        "storage": "Archived" if row["archived"] else "Pending",
        "published": bool(row["published"]),
        "publicationError": row["error"],
    }


@router.get("/v1/events/{event_id}/status")
async def event_status(event_id: UUID, rt: Runtime = _runtime_dependency) -> dict[str, Any]:
    row = require_event(rt, event_id)
    result = rt.state.result(event_id)
    return {
        "event_id": str(event_id),
        "archived": bool(row["archived"]),
        "published": bool(row["published"]),
        "status": result["status"]
        if result
        else "queued"
        if row["archived"]
        else "pending_archive",
        "reason": result.get("reason") if result else row["error"],
    }


@router.get("/v1/events/{event_id}/normalized")
async def normalized_event(
    event_id: UUID, revision: int = Query(1, ge=1), rt: Runtime = _runtime_dependency
) -> dict[str, Any]:
    require_event(rt, event_id)
    result = rt.state.result(event_id, revision)
    if result is None:
        raise HTTPException(409, "This revision has not finished processing")
    if result["status"] != "normalized":
        raise HTTPException(409, {"status": result["status"], "reason": result["reason"]})
    return result["normalized"]  # type: ignore[no-any-return]


@router.get("/v1/events/{event_id}/evidence")
async def evidence(event_id: UUID, rt: Runtime = _runtime_dependency) -> dict[str, Any]:
    require_event(rt, event_id)
    raw = await rt.evidence.get(event_id)
    if raw is None:
        raise HTTPException(409, "Evidence archival is pending")
    result = rt.state.result(event_id)
    return {
        "event_id": str(event_id),
        "raw_sha256": raw.raw_sha256,
        "integrity_verified": raw.verify_integrity(),
        "payload_base64": base64.b64encode(raw.raw_bytes).decode(),
        "raw_text": raw.raw_bytes.decode("utf-8", errors="replace"),
        "byte_length": len(raw.raw_bytes),
        "certificate": result["normalized"]["certificate"]
        if result and result["normalized"]
        else None,
    }


@router.get("/v1/events/{event_id}/raw")
async def raw_download(event_id: UUID, rt: Runtime = _runtime_dependency) -> Response:
    require_event(rt, event_id)
    raw = await rt.evidence.get(event_id)
    if raw is None:
        raise HTTPException(409, "Evidence archival is pending")
    return Response(
        raw.raw_bytes,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{event_id}.bin"',
            "X-Raw-SHA256": raw.raw_sha256,
        },
    )


@router.get("/api/events")
async def events(
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    rt: Runtime = _runtime_dependency,
) -> list[dict[str, Any]]:
    return [view(rt, row) for row in rt.state.events(limit, offset)]


@router.get("/api/events/{event_id}")
async def event(event_id: UUID, rt: Runtime = _runtime_dependency) -> dict[str, Any]:
    return view(rt, require_event(rt, event_id))


async def pipeline_data(rt: Runtime) -> list[dict[str, Any]]:
    health = await rt.health()
    counts = rt.state.counts()
    rt.governance.reload()
    definitions = [
        ("sources", "Ingestion", True, "Durable ingestion intents", str(counts["total"])),
        (
            "minio",
            "Raw archive",
            health["checks"]["minio"],
            "Original bytes preserved",
            str(counts["archived"]),
        ),
        (
            "kafka",
            "Kafka / Redpanda",
            health["checks"]["kafka"],
            "TCP reachability",
            f"{counts['pending_publication']} pending publication",
        ),
        (
            "worker",
            "Normalization worker",
            health["checks"]["worker"],
            health["worker"].get("status", "No heartbeat"),
            health["worker"].get("at", "—"),
        ),
        (
            "parser",
            "Parser registry",
            rt.governance.registry.verify_history(),
            "Approved releases",
            str(len(rt.governance.registry.history)),
        ),
        ("ocsf", "OCSF", True, "Validated outputs", str(counts["normalized"])),
        (
            "provenance",
            "Quarantine",
            True,
            "Evidence retained for review",
            str(counts["quarantined"]),
        ),
    ]
    return [
        {
            "id": key,
            "name": name,
            "status": "healthy" if ok else "failed",
            "description": description,
            "metric": metric,
        }
        for key, name, ok, description, metric in definitions
    ]


@router.get("/api/pipeline/status")
async def pipeline(rt: Runtime = _runtime_dependency) -> list[dict[str, Any]]:
    return await pipeline_data(rt)


@router.get("/api/dashboard")
async def dashboard(rt: Runtime = _runtime_dependency) -> dict[str, Any]:
    counts = rt.state.counts()
    stats = [
        {
            "label": label,
            "value": counts[key],
            "change": "Persisted local total",
            "direction": "flat",
            "icon": icon,
            "tone": "blue",
        }
        for key, label, icon in [
            ("archived", "Archived", "inbox"),
            ("normalized", "Normalized", "braces"),
            ("quarantined", "Quarantined", "shield"),
            ("pending_publication", "Awaiting publication", "blocks"),
        ]
    ]
    return {
        "stats": stats,
        "pipeline": await pipeline_data(rt),
        "events": [view(rt, row) for row in rt.state.events(5)],
        "total": counts["total"],
    }


@router.get("/api/ingestion/status")
async def ingestion_status(rt: Runtime = _runtime_dependency) -> dict[str, Any]:
    health = await rt.health()
    counts = rt.state.counts()
    hb = health["worker"]
    services = []
    for name, key, address in [
        ("Kafka / Redpanda", "kafka", rt.settings.kafka_bootstrap_servers),
        ("MinIO evidence store", "minio", rt.settings.minio_endpoint),
        ("API ingestion", "state", "SQLite outbox"),
    ]:
        services.append(
            {
                "name": name,
                "status": "healthy" if health["checks"][key] else "failed",
                "detail": "Available" if health["checks"][key] else "Unavailable",
                "facts": [["Endpoint", address]],
            }
        )
    return {
        "services": services,
        "worker": {
            "workerId": rt.settings.kafka_consumer_group,
            "status": hb.get("status", "stopped") if health["checks"]["worker"] else "stopped",
            "kafkaConnected": health["checks"]["kafka"],
            "minioConnected": health["checks"]["minio"],
            "currentJob": hb.get("current_job", hb.get("error", "No recent heartbeat")),
            "eventsProcessed": counts["normalized"],
            "eventsFailed": counts["quarantined"],
            "lastHeartbeat": hb.get("at", "—"),
        },
        "recent": [view(rt, row) for row in rt.state.events(20)],
    }


class WorkerCommand(BaseModel):
    action: Literal["pause", "resume"]


@router.post("/api/worker/control", dependencies=[Depends(operator)])
async def worker_control(body: WorkerCommand, rt: Runtime = _runtime_dependency) -> dict[str, str]:
    rt.state.set("worker-command", "paused" if body.action == "pause" else "running")
    return {"requested": body.action}


@router.get("/api/parsers")
async def parsers(rt: Runtime = _runtime_dependency) -> list[dict[str, Any]]:
    rt.governance.reload()
    rows = []
    for release in rt.governance.registry.history:
        pack = release.signed_pack.pack
        active = rt.governance.registry.active_release(pack.source_key)
        rows.append(
            {
                "id": str(release.registry_revision),
                "name": pack.display_name,
                "key": pack.source_key,
                "format": pack.parser_format.value.upper(),
                "version": pack.version,
                "status": "Active" if active == release else "Superseded",
                "qualification": "Passed",
                "fixtures": len(pack.fixtures),
                "lastUsed": "See event results",
                "processed": "—",
                "pack": pack.model_dump(mode="json"),
                "release": release.model_dump(mode="json"),
                "registryRevision": release.registry_revision,
            }
        )
    return rows


@router.get("/api/governance/audit")
async def audit(rt: Runtime = _runtime_dependency) -> list[dict[str, Any]]:
    rt.governance.reload()
    return [
        {
            "kind": item.event_type.split(".")[-1],
            "action": item.event_type,
            "time": item.occurred_at.isoformat(),
            "subject": item.artifact_sha256,
            "detail": str(item.details),
            "actor": item.actor_id,
            "entry_hash": item.entry_hash,
        }
        for item in reversed(rt.governance.control.audit_log.entries)
    ]


@router.get("/api/governance/proposals")
async def proposals(rt: Runtime = _runtime_dependency) -> list[dict[str, Any]]:
    rt.governance.reload()
    return [p.model_dump(mode="json") for p in rt.governance.control.proposals]


class ProposalRequest(BaseModel):
    pack: SourceDefinitionPack
    proposed_by: str = Field(default="demo-author", min_length=1)


@router.post("/api/governance/proposals", dependencies=[Depends(operator)])
async def propose(body: ProposalRequest, rt: Runtime = _runtime_dependency) -> dict[str, Any]:
    async with rt.control_lock:
        rt.governance.reload()
        proposal = rt.governance.control.submit(pack=body.pack, proposed_by=body.proposed_by)
        rt.governance.save()
    return proposal.model_dump(mode="json")


class ProposalAction(BaseModel):
    action: Literal["approve", "reject", "qualify", "activate"]
    reason: str = Field(
        default="Operator reviewed parser definition and fixture expectations", min_length=8
    )
    event_ids: list[UUID] = Field(default_factory=list, max_length=1000)


@router.post("/api/governance/proposals/{proposal_id}", dependencies=[Depends(operator)])
async def proposal_action(
    proposal_id: str, body: ProposalAction, rt: Runtime = _runtime_dependency
) -> dict[str, Any]:
    async with rt.control_lock:
        rt.governance.reload()
        control = rt.governance.control
        try:
            if body.action in {"approve", "reject"}:
                updated = control.review(
                    proposal_id=proposal_id,
                    reviewer_id="demo-reviewer",
                    reviewer_signer=rt.governance.signers["demo-reviewer"],
                    decision=ReviewDecision(body.action),
                    reason=body.reason,
                )
            elif body.action == "qualify":
                updated = control.qualify(proposal_id=proposal_id, actor_id="qualification-runner")
            else:
                candidate = control.get(proposal_id).pack
                active = rt.governance.registry.active_pack(candidate.source_key)
                comparison = None
                if active:
                    sample_events = []
                    for event_id in dict.fromkeys(body.event_ids):
                        raw = await rt.evidence.get(event_id)
                        if raw is None or raw.source.source_type != candidate.source_key:
                            raise ValueError("comparison event missing or source mismatch")
                        sample_events.append(raw)
                    comparison = ParserComparator(rt.catalog).evaluate(
                        active_pack=active, candidate_pack=candidate, events=sample_events
                    )
                updated = await control.activate(
                    proposal_id=proposal_id, actor_id="demo-operator", comparison_report=comparison
                )
                if comparison:
                    rt.state.set(
                        "comparison:" + comparison.report_sha256, comparison.model_dump(mode="json")
                    )
            rt.governance.save()
        except (ValueError, KeyError) as exc:
            raise HTTPException(409, str(exc)) from exc
    return updated.model_dump(mode="json")


@router.get("/api/parsers/{revision}/proof")
async def parser_proof(revision: int, rt: Runtime = _runtime_dependency) -> dict[str, Any]:
    rt.governance.reload()
    try:
        leaf, proof, checkpoint = rt.governance.registry.release_evidence(revision)
    except (KeyError, ValueError) as exc:
        raise HTTPException(404, str(exc)) from exc
    return {
        "leaf": leaf.model_dump(mode="json"),
        "proof": proof.model_dump(mode="json"),
        "checkpoint": checkpoint.model_dump(mode="json"),
        "registry_verified": rt.governance.registry.verify_history(),
    }


class ReplayRequest(BaseModel):
    event_ids: list[UUID] = Field(min_length=1, max_length=100)
    registry_revision: int = Field(ge=1)
    reason: str = Field(min_length=8, max_length=1024)
    requested_by: str = Field(default="demo-analyst", min_length=1)


@router.get("/api/replay")
async def replays(rt: Runtime = _runtime_dependency) -> list[dict[str, Any]]:
    return rt.state.replays()


@router.post("/api/replay", dependencies=[Depends(operator)])
async def request_replay(body: ReplayRequest, rt: Runtime = _runtime_dependency) -> dict[str, Any]:
    async with rt.control_lock:
        rt.governance.reload()
        try:
            release = rt.governance.registry.release_at(body.registry_revision)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        if len(set(body.event_ids)) != len(body.event_ids):
            raise HTTPException(422, "Duplicate event IDs")
        if body.requested_by == "replay-approver":
            raise HTTPException(422, "Requester cannot be the replay approver")
        for event_id in body.event_ids:
            raw = decode_event(require_event(rt, event_id)["document"])
            if raw.source.source_type != release.signed_pack.pack.source_key:
                raise HTTPException(422, "Replay source does not match selected parser")
        revision = rt.state.get("next-replay-revision", 2)
        rt.state.set("next-replay-revision", revision + 1)
        job = {
            "id": str(uuid4()),
            "status": "requested",
            "request": body.model_dump(mode="json"),
            "normalization_revision": revision,
            "created_at": datetime.now(UTC).isoformat(),
        }
        rt.state.save_replay(job["id"], job)
    return job


@router.post("/api/replay/{job_id}/approve", dependencies=[Depends(operator)])
async def approve_replay(job_id: UUID, rt: Runtime = _runtime_dependency) -> dict[str, Any]:
    async with rt.control_lock:
        job = next((item for item in rt.state.replays() if item["id"] == str(job_id)), None)
        if job is None:
            raise HTTPException(404, "Replay request not found")
        if job["status"] != "requested":
            return job
        rt.governance.reload()
        body = ReplayRequest.model_validate(job["request"])
        release = rt.governance.registry.release_at(body.registry_revision)
        manifest = ReplayManifest.issue(
            source_key=release.signed_pack.pack.source_key,
            registry_revision=body.registry_revision,
            pack_sha256=release.signed_pack.pack.sha256(),
            event_ids=tuple(body.event_ids),
            normalization_revision=job["normalization_revision"],
            reason=body.reason,
            requested_by=body.requested_by,
            approved_by="replay-approver",
            approver_signer=rt.governance.signers["replay-approver"],
        )
        job.update(status="approved", manifest=manifest.model_dump(mode="json"))
        rt.state.save_replay(job["id"], job)
    return job


class CopilotRequest(BaseModel):
    event_ids: list[UUID] = Field(min_length=1, max_length=20)
    version: str = Field(default="1.1.0", pattern=r"^\d+\.\d+\.\d+$")


@router.post("/api/copilot/proposals", dependencies=[Depends(operator)])
async def copilot_proposal(
    body: CopilotRequest, rt: Runtime = _runtime_dependency
) -> dict[str, Any]:
    from drishti.copilot.local import AirGappedSchemaCopilot

    samples = []
    for event_id in body.event_ids:
        require_event(rt, event_id)
        raw = await rt.evidence.get(event_id)
        if raw is None:
            raise HTTPException(409, "Sample has not been archived")
        samples.append(raw.raw_bytes)
    try:
        suggestion = AirGappedSchemaCopilot().propose(samples)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    async with rt.control_lock:
        rt.governance.reload()
        pack = suggestion.pack.model_copy(update={"version": body.version})
        proposal = rt.governance.control.submit(pack=pack, proposed_by="local-copilot")
        rt.governance.save()
    return {
        "suggestion": suggestion.model_dump(mode="json"),
        "proposal": proposal.model_dump(mode="json"),
    }
