from __future__ import annotations

import statistics
import time
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field

from drishti.domain.events import RawEvent, SourceRef
from drishti.governance.crypto import sha256_json
from drishti.ocsf.catalog import OcsfCatalog
from drishti.parsers.common import ParseError
from drishti.parsers.engine import DeterministicParserEngine
from drishti.parsers.models import SourceDefinitionPack
from drishti.provenance.lineage import ParserIdentity


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"


class QualificationCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    status: CheckStatus
    detail: str


class QualificationReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    pack_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    generated_at: datetime
    checks: tuple[QualificationCheck, ...]
    passed: bool
    report_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    def unsigned_document(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"report_sha256"})

    def verify(self) -> bool:
        return self.report_sha256 == sha256_json(self.unsigned_document())

    @classmethod
    def issue(cls, *, pack_sha256: str, checks: list[QualificationCheck]) -> QualificationReport:
        generated_at = datetime.now(UTC)
        passed = bool(checks) and all(check.status is CheckStatus.PASS for check in checks)
        provisional = cls(
            pack_sha256=pack_sha256,
            generated_at=generated_at,
            checks=tuple(checks),
            passed=passed,
            report_sha256="0" * 64,
        )
        return provisional.model_copy(
            update={"report_sha256": sha256_json(provisional.unsigned_document())}
        )


class QualificationGate:
    """Fail-closed qualification for declarative, non-executable parser packs."""

    def __init__(self, catalog: OcsfCatalog, *, benchmark_iterations: int = 25) -> None:
        self._catalog = catalog
        self._engine = DeterministicParserEngine(catalog)
        self._benchmark_iterations = benchmark_iterations

    def qualify(self, pack: SourceDefinitionPack) -> QualificationReport:
        checks: list[QualificationCheck] = []
        checks.append(self._check_class(pack))
        for fixture_index, _fixture in enumerate(pack.fixtures):
            checks.append(self._check_fixture(pack, fixture_index))
        checks.extend(self._adversarial_checks(pack))
        checks.append(self._check_budget(pack))
        return QualificationReport.issue(pack_sha256=pack.sha256(), checks=checks)

    def _check_class(self, pack: SourceDefinitionPack) -> QualificationCheck:
        class_name = self._catalog.class_name_for_uid(pack.target_class_uid)
        if class_name is None:
            return self._failed("ocsf-contract", "target class is absent from the pinned bundle")
        if pack.ocsf_version != self._catalog.identity.ocsf_version:
            return self._failed("ocsf-contract", "pack OCSF version is not the pinned version")
        return self._passed("ocsf-contract", f"targets pinned class {class_name}")

    def _check_fixture(self, pack: SourceDefinitionPack, fixture_index: int) -> QualificationCheck:
        fixture = pack.fixtures[fixture_index]
        try:
            normalized = self._normalize(pack, fixture.raw_bytes(), fixture_index)
            mismatches = []
            for path, expected in fixture.expected_fields.items():
                actual = self._get_path(normalized.ocsf_event, path)
                if actual != expected:
                    mismatches.append(f"{path}: expected {expected!r}, got {actual!r}")
            if not normalized.certificate.fully_accounted:
                mismatches.append("raw byte conservation certificate is incomplete")
            if mismatches:
                return self._failed(f"fixture:{fixture.name}", "; ".join(mismatches))
        except Exception as exc:  # qualification converts every parser failure into a report
            return self._failed(f"fixture:{fixture.name}", f"{type(exc).__name__}: {exc}")
        return self._passed(f"fixture:{fixture.name}", "OCSF mapping and byte proof verified")

    def _adversarial_checks(self, pack: SourceDefinitionPack) -> list[QualificationCheck]:
        sample = pack.fixtures[0].raw_bytes()
        mutations = {
            "embedded-nul": sample[:1] + b"\x00" + sample[1:],
            "truncated": sample[: max(1, len(sample) // 4)],
            "oversized": sample + b"X" * max(1, pack.budget.max_event_bytes - len(sample) + 1),
        }
        checks: list[QualificationCheck] = []
        for name, mutation in mutations.items():
            try:
                self._engine.parse(mutation, pack)
                self._engine.map_event(self._engine.parse(mutation, pack), pack)
            except (ParseError, ValueError):
                checks.append(self._passed(f"adversarial:{name}", "malformed input rejected"))
            else:
                checks.append(self._failed(f"adversarial:{name}", "malformed input was accepted"))
        return checks

    def _check_budget(self, pack: SourceDefinitionPack) -> QualificationCheck:
        samples_ms: list[float] = []
        raw = pack.fixtures[0].raw_bytes()
        try:
            for _ in range(self._benchmark_iterations):
                started = time.perf_counter_ns()
                self._engine.parse(raw, pack)
                samples_ms.append((time.perf_counter_ns() - started) / 1_000_000)
        except Exception as exc:
            return self._failed("resource-budget", f"benchmark failed: {exc}")
        p95 = statistics.quantiles(samples_ms, n=20)[18] if len(samples_ms) > 1 else samples_ms[0]
        if p95 > pack.budget.max_p95_parse_ms:
            return self._failed(
                "resource-budget",
                f"p95 {p95:.3f} ms exceeds {pack.budget.max_p95_parse_ms:.3f} ms",
            )
        return self._passed("resource-budget", f"p95 {p95:.3f} ms")

    def _normalize(self, pack: SourceDefinitionPack, raw: bytes, fixture_index: int) -> Any:
        raw_event = RawEvent.create(
            event_id=uuid5(NAMESPACE_URL, f"qualification:{pack.sha256()}:{fixture_index}"),
            trace_id=uuid5(NAMESPACE_URL, f"qualification-trace:{pack.sha256()}:{fixture_index}"),
            source=SourceRef(
                tenant_id="qualification",
                source_id=pack.source_key,
                source_type=pack.parser_format.value,
            ),
            raw_bytes=raw,
            idempotency_key=None,
            observed_at=None,
            received_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        return self._engine.normalize(
            raw_event=raw_event,
            pack=pack,
            parser_identity=ParserIdentity(
                bundle_uid=f"{pack.pack_uid}@{pack.version}",
                bundle_sha256=pack.sha256(),
            ),
        )

    @staticmethod
    def _get_path(document: dict[str, Any], path: str) -> Any:
        value: Any = document
        for part in path.split("."):
            if not isinstance(value, dict) or part not in value:
                return None
            value = value[part]
        return value

    @staticmethod
    def _passed(name: str, detail: str) -> QualificationCheck:
        return QualificationCheck(name=name, status=CheckStatus.PASS, detail=detail)

    @staticmethod
    def _failed(name: str, detail: str) -> QualificationCheck:
        return QualificationCheck(name=name, status=CheckStatus.FAIL, detail=detail)
