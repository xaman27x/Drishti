from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from drishti.config import Settings
from drishti.governance.registry import RegistryRelease
from drishti.parsers.engine import DeterministicParserEngine
from drishti.pipeline.ports import RawEvidenceStore
from drishti.provenance.lineage import ParserIdentity
from drishti.runtime.governance import Governance
from drishti.runtime.state import State
from drishti.runtime.storage import Artifacts
from drishti.safety.format_detection import DriftStatus, FormatChangeDetector, FormatFingerprinter


class Processor:
    def __init__(
        self,
        state: State,
        evidence: RawEvidenceStore,
        artifacts: Artifacts,
        governance: Governance,
        settings: Settings,
    ) -> None:
        self.state, self.evidence, self.artifacts = state, evidence, artifacts
        self.governance, self.settings = governance, settings
        self.engine = DeterministicParserEngine(governance.catalog)

    async def process(
        self,
        event_id: UUID,
        *,
        expected_sha256: str | None = None,
        revision: int = 1,
        release: RegistryRelease | None = None,
    ) -> dict[str, Any]:
        # Check archived bytes even on a duplicate delivery.
        raw = await self.evidence.get(event_id)
        if raw is None:
            raise RuntimeError("referenced raw evidence is not yet available")
        if not raw.verify_integrity() or (
            expected_sha256 is not None and raw.raw_sha256 != expected_sha256
        ):
            raise ValueError("archived evidence digest differs from notification")
        existing = self.state.result(event_id, revision)
        if existing:
            if release and existing.get("pack_sha256") != release.signed_pack.pack.sha256():
                raise ValueError("output revision already belongs to a different parser")
            return existing
        object_key = f"results/{event_id}/{revision}.json"
        stored = await self.artifacts.get(object_key)
        if stored:
            if stored["raw_sha256"] != raw.raw_sha256 or (
                release and stored.get("pack_sha256") != release.signed_pack.pack.sha256()
            ):
                raise ValueError("result artifact identity mismatch")
            self.state.save_result(
                event_id,
                revision,
                stored,
                drift_key=stored.get("drift_key"),
                drift=stored.get("drift_state"),
            )
            return stored
        self.governance.reload()
        chosen = release or self.governance.registry.active_release(raw.source.source_type)
        start = time.perf_counter()
        result: dict[str, Any] = {
            "event_id": str(event_id),
            "revision": revision,
            "raw_sha256": raw.raw_sha256,
            "status": "quarantined",
            "reason": None,
            "normalized": None,
            "processed_at": datetime.now(UTC).isoformat(),
            "artifact_key": object_key,
        }
        if chosen is None:
            result["reason"] = "No approved parser for source_type: " + raw.source.source_type
        elif chosen.signed_pack.pack.source_key != raw.source.source_type:
            result["reason"] = "Pinned parser source does not match evidence source"
        else:
            pack = chosen.signed_pack.pack
            result.update(
                parser=f"{pack.pack_uid}@{pack.version}",
                pack_sha256=pack.sha256(),
                registry_revision=chosen.registry_revision,
            )
            identity = ParserIdentity(bundle_uid=result["parser"], bundle_sha256=pack.sha256())
            try:
                normalized = self.engine.normalize(
                    raw_event=raw,
                    pack=pack,
                    parser_identity=identity,
                    normalization_revision=revision,
                )
            except ValueError as exc:
                result["reason"] = f"{type(exc).__name__}: {exc}"
                normalized = None
            if revision == 1:
                # Baseline is learned only from parser-accepted samples. Keep state
                # keyed by tenant, device AND approved pack; unrelated sources cannot mix.
                source_key = hashlib.sha256(
                    json.dumps([raw.source.tenant_id, raw.source.source_id, pack.sha256()]).encode()
                ).hexdigest()
                drift_key = "drift:" + source_key
                secret = hashlib.sha256(
                    self.governance.signers["registry-root"].private_key_base64().encode()
                ).digest()
                detector = FormatChangeDetector(
                    source_key=source_key,
                    fingerprinter=FormatFingerprinter(secret),
                    baseline_size=self.settings.drift_baseline_size,
                    window_size=self.settings.drift_window_size,
                )
                snapshot = self.state.get(drift_key, {})
                detector.restore(snapshot)
                if (
                    normalized is not None
                    or len(snapshot.get("baseline", [])) >= self.settings.drift_baseline_size
                ):
                    decision = detector.observe(event_id=event_id, raw=raw.raw_bytes)
                    result.update(
                        drift=decision.model_dump(mode="json"),
                        drift_key=drift_key,
                        drift_state=detector.snapshot(),
                    )
                    if decision.status == DriftStatus.QUARANTINE:
                        result["reason"] = decision.reason
                        normalized = None
            if normalized is not None:
                result.update(
                    status="normalized", normalized=normalized.model_dump(mode="json"), reason=None
                )
        result["duration_ms"] = round((time.perf_counter() - start) * 1000, 3)
        # A storage failure propagates: no Kafka commit and no lost output.
        result = await self.artifacts.put(object_key, result)
        self.state.save_result(
            event_id,
            revision,
            result,
            drift_key=result.get("drift_key"),
            drift=result.get("drift_state"),
        )
        return result

    async def handle_message(self, payload: bytes, message_key: str) -> None:
        try:
            envelope = json.loads(payload)
            if envelope.get("type") != "in.drishti.raw.archived.v1":
                raise ValueError("unsupported event type")
            event_id = UUID(envelope["data"]["event_id"])
            digest = envelope["data"]["raw_sha256"]
            if not isinstance(digest, str) or len(digest) != 64:
                raise ValueError("invalid digest")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            # Persist poison messages before allowing the consumer to advance.
            import base64

            self.state.deadletter(
                message_key,
                {"reason": str(exc), "payload_base64": base64.b64encode(payload).decode()},
            )
            return
        await self.process(event_id, expected_sha256=digest)
