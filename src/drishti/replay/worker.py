from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from drishti.domain.events import RawEvent
from drishti.governance.crypto import PublicKeyRing, sha256_json
from drishti.governance.registry import ParserRegistry
from drishti.normalization.models import CertifiedNormalizedEvent
from drishti.ocsf.catalog import OcsfCatalog
from drishti.parsers.engine import DeterministicParserEngine
from drishti.provenance.lineage import ParserIdentity
from drishti.replay.models import (
    ReplayEventResult,
    ReplayEventStatus,
    ReplayManifest,
    ReplayResult,
)


class ReplayEvidenceReader(Protocol):
    async def get(self, event_id: UUID) -> RawEvent | None: ...


class NormalizedEventSink(Protocol):
    async def put_if_absent(self, event: CertifiedNormalizedEvent) -> bool: ...


class ControlledReplayWorker:
    def __init__(
        self,
        *,
        registry: ParserRegistry,
        catalog: OcsfCatalog,
        evidence: ReplayEvidenceReader,
        sink: NormalizedEventSink,
        replay_approver_keys: PublicKeyRing,
    ) -> None:
        self._registry = registry
        self._engine = DeterministicParserEngine(catalog)
        self._evidence = evidence
        self._sink = sink
        self._approver_keys = replay_approver_keys

    async def run(self, manifest: ReplayManifest) -> ReplayResult:
        if not manifest.verify(self._approver_keys):
            raise ValueError("controlled replay approval signature is invalid or untrusted")
        if not self._registry.verify_history():
            raise ValueError("parser registry integrity check failed")
        release = self._registry.release_at(manifest.registry_revision)
        pack = release.signed_pack.pack
        if pack.source_key != manifest.source_key or pack.sha256() != manifest.pack_sha256:
            raise ValueError("replay manifest does not match its pinned registry release")

        started_at = datetime.now(UTC)
        results: list[ReplayEventResult] = []
        identity = ParserIdentity(
            bundle_uid=f"{pack.pack_uid}@{pack.version}",
            bundle_sha256=pack.sha256(),
        )
        for event_id in manifest.event_ids:
            raw_event = await self._evidence.get(event_id)
            if raw_event is None:
                results.append(
                    ReplayEventResult(event_id=event_id, status=ReplayEventStatus.MISSING)
                )
                continue
            try:
                normalized = self._engine.normalize(
                    raw_event=raw_event,
                    pack=pack,
                    parser_identity=identity,
                    normalization_revision=manifest.normalization_revision,
                )
                await self._sink.put_if_absent(normalized)
            except ValueError as exc:
                results.append(
                    ReplayEventResult(
                        event_id=event_id,
                        status=ReplayEventStatus.REJECTED,
                        detail=f"{type(exc).__name__}: {exc}",
                    )
                )
            else:
                results.append(
                    ReplayEventResult(
                        event_id=event_id,
                        status=ReplayEventStatus.NORMALIZED,
                        normalized_event_id=normalized.normalized_event_id,
                    )
                )
        completed_at = datetime.now(UTC)
        unsigned = {
            "replay_id": str(manifest.replay_id),
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "results": [result.model_dump(mode="json") for result in results],
        }
        return ReplayResult(
            replay_id=manifest.replay_id,
            started_at=started_at,
            completed_at=completed_at,
            results=tuple(results),
            result_sha256=sha256_json(unsigned),
        )
