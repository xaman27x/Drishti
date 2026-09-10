from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Protocol

from drishti.domain.events import RawEvent
from drishti.normalization.models import CertifiedNormalizedEvent
from drishti.ocsf.catalog import OcsfCatalog
from drishti.parsers.cef import CefParser
from drishti.parsers.common import ParseError, ParseResult
from drishti.parsers.models import ParserFormat, SourceDefinitionPack, Transform
from drishti.parsers.rfc5424 import Rfc5424Parser
from drishti.provenance.lineage import ParserIdentity


class MappingError(ValueError):
    """A validated source pack could not map a parsed event."""


class Parser(Protocol):
    def parse(self, raw: bytes) -> ParseResult: ...


class DeterministicParserEngine:
    """Executes an allowlisted parser and transform set; never generated code."""

    def __init__(self, catalog: OcsfCatalog) -> None:
        self._catalog = catalog
        self._parsers: dict[ParserFormat, Parser] = {
            ParserFormat.RFC5424: Rfc5424Parser(),
            ParserFormat.CEF: CefParser(),
        }

    def parse(self, raw: bytes, pack: SourceDefinitionPack) -> ParseResult:
        if len(raw) > pack.budget.max_event_bytes:
            raise ParseError(
                f"event contains {len(raw)} bytes; pack limit is {pack.budget.max_event_bytes}"
            )
        if b"\x00" in raw:
            raise ParseError("NUL bytes are forbidden in text log formats")
        return self._parsers[pack.parser_format].parse(raw)

    def map_event(self, parsed: ParseResult, pack: SourceDefinitionPack) -> dict[str, Any]:
        event: dict[str, Any] = {}
        captures = parsed.captures
        for rule in pack.rules:
            if rule.source_capture is not None:
                source = captures.get(rule.source_capture)
                if source is None:
                    if rule.required:
                        raise MappingError(f"required capture is missing: {rule.source_capture}")
                    continue
                value = self._transform(source, rule.transform)
            else:
                value = rule.constant
            self._set_path(event, rule.target_path, value)

        class_uid = event.get("class_uid")
        if class_uid != pack.target_class_uid:
            raise MappingError(
                f"pack targets class {pack.target_class_uid}, but rules produced {class_uid!r}"
            )
        self._derive_endpoint_uids(event)
        return event

    def normalize(
        self,
        *,
        raw_event: RawEvent,
        pack: SourceDefinitionPack,
        parser_identity: ParserIdentity,
        normalization_revision: int = 1,
    ) -> CertifiedNormalizedEvent:
        parsed = self.parse(raw_event.raw_bytes, pack)
        event = self.map_event(parsed, pack)
        return CertifiedNormalizedEvent.issue(
            raw_event=raw_event,
            ocsf_event=event,
            claims=parsed.evidence_claims(pack.rules),
            parser=parser_identity,
            catalog=self._catalog,
            normalization_revision=normalization_revision,
        )

    @staticmethod
    def _transform(value: str, transform: Transform) -> Any:
        if transform is Transform.IDENTITY:
            return value
        if transform is Transform.INTEGER:
            try:
                return int(value)
            except ValueError as exc:
                raise MappingError(f"{value!r} is not an integer") from exc
        if transform is Transform.IP_ADDRESS:
            try:
                return str(ipaddress.ip_address(value))
            except ValueError as exc:
                raise MappingError(f"{value!r} is not an IP address") from exc
        if transform is Transform.LOWERCASE:
            return value.lower()
        if transform is Transform.RFC3339_TO_EPOCH_MS:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise MappingError(f"{value!r} is not RFC3339 datetime data") from exc
            if parsed.tzinfo is None:
                raise MappingError("RFC3339 event time must include an offset")
            return int(parsed.timestamp() * 1_000)
        if transform is Transform.CEF_SEVERITY_TO_OCSF:
            severity = DeterministicParserEngine._bounded_integer(value, 0, 10, "CEF severity")
            return (
                1
                if severity <= 1
                else 2
                if severity <= 3
                else 3
                if severity <= 6
                else 4
                if severity <= 8
                else 5
            )
        if transform is Transform.SYSLOG_PRI_TO_OCSF_SEVERITY:
            priority = DeterministicParserEngine._bounded_integer(value, 0, 191, "syslog PRI")
            return {0: 6, 1: 5, 2: 5, 3: 4, 4: 3, 5: 2, 6: 1, 7: 1}[priority % 8]
        raise MappingError(f"unsupported transform: {transform}")

    @staticmethod
    def _bounded_integer(value: str, minimum: int, maximum: int, label: str) -> int:
        try:
            result = int(value)
        except ValueError as exc:
            raise MappingError(f"{label} must be an integer") from exc
        if not minimum <= result <= maximum:
            raise MappingError(f"{label} must be between {minimum} and {maximum}")
        return result

    @staticmethod
    def _set_path(document: dict[str, Any], path: str, value: Any) -> None:
        parts = path.split(".")
        cursor = document
        for part in parts[:-1]:
            existing = cursor.setdefault(part, {})
            if not isinstance(existing, dict):
                raise MappingError(f"mapping path collision at {part}")
            cursor = existing
        cursor[parts[-1]] = value

    @staticmethod
    def _derive_endpoint_uids(event: dict[str, Any]) -> None:
        for field in ("src_endpoint", "dst_endpoint"):
            endpoint = event.get(field)
            if isinstance(endpoint, dict) and "ip" in endpoint and "uid" not in endpoint:
                endpoint["uid"] = endpoint["ip"]
