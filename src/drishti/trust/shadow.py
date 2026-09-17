from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from drishti.domain.events import RawEvent
from drishti.governance.crypto import sha256_json
from drishti.ocsf.catalog import OcsfCatalog
from drishti.parsers.engine import DeterministicParserEngine
from drishti.parsers.models import SourceDefinitionPack
from drishti.provenance.lineage import ParserIdentity

DEFAULT_CRITICAL_PATHS = (
    "activity_id",
    "class_uid",
    "time",
    "severity_id",
    "src_endpoint.ip",
    "dst_endpoint.ip",
)


class SemanticDelta(BaseModel):
    model_config = ConfigDict(frozen=True)

    raw_event_id: UUID
    raw_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    active_error: str | None = None
    candidate_error: str | None = None
    changed_paths: tuple[str, ...] = ()
    critical_changed_paths: tuple[str, ...] = ()
    active_conservation_score: float | None = None
    candidate_conservation_score: float | None = None


class ShadowReport(BaseModel):
    """Counterfactual result of running active and candidate packs on identical evidence."""

    model_config = ConfigDict(frozen=True)

    source_key: str
    active_pack_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_pack_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    generated_at: datetime
    total_events: int = Field(ge=1)
    candidate_failures: int = Field(ge=0)
    critical_regressions: int = Field(ge=0)
    semantic_change_ratio: float = Field(ge=0, le=1)
    minimum_candidate_conservation: float = Field(ge=0, le=1)
    deltas: tuple[SemanticDelta, ...]
    report_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    def unsigned_document(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"report_sha256"})

    def verify(self) -> bool:
        return self.report_sha256 == sha256_json(self.unsigned_document())


class ShadowEvaluator:
    def __init__(
        self,
        catalog: OcsfCatalog,
        *,
        critical_paths: tuple[str, ...] = DEFAULT_CRITICAL_PATHS,
    ) -> None:
        self._engine = DeterministicParserEngine(catalog)
        self._critical_paths = frozenset(critical_paths)

    def evaluate(
        self,
        *,
        active_pack: SourceDefinitionPack,
        candidate_pack: SourceDefinitionPack,
        events: list[RawEvent],
    ) -> ShadowReport:
        if not events:
            raise ValueError("shadow evaluation requires at least one raw event")
        if active_pack.source_key != candidate_pack.source_key:
            raise ValueError("shadow packs must target the same source key")
        deltas = tuple(
            self._evaluate_event(
                event=event,
                active_pack=active_pack,
                candidate_pack=candidate_pack,
            )
            for event in events
        )
        candidate_failures = sum(delta.candidate_error is not None for delta in deltas)
        critical_regressions = sum(bool(delta.critical_changed_paths) for delta in deltas)
        semantic_changes = sum(bool(delta.changed_paths) for delta in deltas)
        conservation_scores = [
            delta.candidate_conservation_score
            for delta in deltas
            if delta.candidate_conservation_score is not None
        ]
        provisional = ShadowReport(
            source_key=active_pack.source_key,
            active_pack_sha256=active_pack.sha256(),
            candidate_pack_sha256=candidate_pack.sha256(),
            generated_at=datetime.now(UTC),
            total_events=len(events),
            candidate_failures=candidate_failures,
            critical_regressions=critical_regressions,
            semantic_change_ratio=semantic_changes / len(events),
            minimum_candidate_conservation=(
                min(conservation_scores) if conservation_scores else 0.0
            ),
            deltas=deltas,
            report_sha256="0" * 64,
        )
        return provisional.model_copy(
            update={"report_sha256": sha256_json(provisional.unsigned_document())}
        )

    def _evaluate_event(
        self,
        *,
        event: RawEvent,
        active_pack: SourceDefinitionPack,
        candidate_pack: SourceDefinitionPack,
    ) -> SemanticDelta:
        active, active_error = self._normalize(event, active_pack, revision=1)
        candidate, candidate_error = self._normalize(event, candidate_pack, revision=2)
        active_event = {} if active is None else active.ocsf_event
        candidate_event = {} if candidate is None else candidate.ocsf_event
        active_flat = self._flatten(active_event)
        candidate_flat = self._flatten(candidate_event)
        changed = tuple(
            sorted(
                path
                for path in set(active_flat) | set(candidate_flat)
                if active_flat.get(path) != candidate_flat.get(path)
            )
        )
        critical = tuple(path for path in changed if path in self._critical_paths)
        if candidate_error is not None:
            critical = tuple(sorted(self._critical_paths))
        return SemanticDelta(
            raw_event_id=event.event_id,
            raw_sha256=event.raw_sha256,
            active_error=active_error,
            candidate_error=candidate_error,
            changed_paths=changed,
            critical_changed_paths=critical,
            active_conservation_score=(
                None if active is None else active.certificate.conservation_score
            ),
            candidate_conservation_score=(
                None if candidate is None else candidate.certificate.conservation_score
            ),
        )

    def _normalize(
        self, event: RawEvent, pack: SourceDefinitionPack, *, revision: int
    ) -> tuple[Any | None, str | None]:
        try:
            normalized = self._engine.normalize(
                raw_event=event,
                pack=pack,
                parser_identity=ParserIdentity(
                    bundle_uid=f"{pack.pack_uid}@{pack.version}",
                    bundle_sha256=pack.sha256(),
                ),
                normalization_revision=revision,
            )
        except ValueError as exc:
            return None, f"{type(exc).__name__}: {exc}"
        return normalized, None

    @classmethod
    def _flatten(cls, value: Any, *, prefix: str = "") -> dict[str, Any]:
        if not isinstance(value, dict):
            return {prefix: value}
        flattened: dict[str, Any] = {}
        for key, member in value.items():
            path = key if not prefix else f"{prefix}.{key}"
            if isinstance(member, dict):
                flattened.update(cls._flatten(member, prefix=path))
            else:
                flattened[path] = member
        return flattened


class PromotionPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    minimum_events: int = Field(default=100, ge=1)
    maximum_candidate_failures: int = Field(default=0, ge=0)
    maximum_critical_regressions: int = Field(default=0, ge=0)
    minimum_conservation_score: float = Field(default=1.0, ge=0, le=1)


class PromotionDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    accepted: bool
    reasons: tuple[str, ...]
    shadow_report_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ShadowPromotionGate:
    def __init__(self, policy: PromotionPolicy | None = None) -> None:
        self.policy = policy or PromotionPolicy()

    def decide(self, report: ShadowReport) -> PromotionDecision:
        reasons: list[str] = []
        if not report.verify():
            reasons.append("shadow report integrity verification failed")
        if report.total_events < self.policy.minimum_events:
            reasons.append(
                f"requires {self.policy.minimum_events} events; received {report.total_events}"
            )
        if report.candidate_failures > self.policy.maximum_candidate_failures:
            reasons.append("candidate parser failure budget exceeded")
        if report.critical_regressions > self.policy.maximum_critical_regressions:
            reasons.append("critical semantic regression budget exceeded")
        if report.minimum_candidate_conservation < self.policy.minimum_conservation_score:
            reasons.append("candidate byte-conservation score is below policy")
        return PromotionDecision(
            accepted=not reasons,
            reasons=tuple(reasons),
            shadow_report_sha256=report.report_sha256,
        )
