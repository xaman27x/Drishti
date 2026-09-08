from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from drishti.parsers.models import FieldRule, ParserFormat
from drishti.provenance.lineage import ByteClaim, ByteDisposition


class ParseError(ValueError):
    """A deterministic parser rejected malformed or unsupported input."""


class SegmentKind(StrEnum):
    CAPTURE = "capture"
    STRUCTURAL = "structural"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Segment:
    start: int
    end: int
    kind: SegmentKind
    name: str | None = None
    value: str | None = None

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError("segment bounds are invalid")
        if self.kind is SegmentKind.CAPTURE and (self.name is None or self.value is None):
            raise ValueError("capture segments require a name and value")


@dataclass(frozen=True, slots=True)
class ParseResult:
    parser_format: ParserFormat
    raw: bytes
    segments: tuple[Segment, ...]

    def __post_init__(self) -> None:
        cursor = 0
        names: set[str] = set()
        for segment in self.segments:
            if segment.start != cursor:
                raise ValueError("parser segments must cover the input contiguously")
            if segment.end > len(self.raw):
                raise ValueError("parser segment exceeds input length")
            if segment.name is not None:
                if segment.name in names:
                    raise ParseError(f"duplicate capture: {segment.name}")
                names.add(segment.name)
            cursor = segment.end
        if cursor != len(self.raw):
            raise ValueError("parser segments must cover the complete input")

    @property
    def captures(self) -> Mapping[str, str]:
        return {
            segment.name: segment.value
            for segment in self.segments
            if segment.kind is SegmentKind.CAPTURE
            and segment.name is not None
            and segment.value is not None
        }

    def evidence_claims(self, rules: tuple[FieldRule, ...]) -> list[ByteClaim]:
        targets = {
            rule.source_capture: rule.target_path
            for rule in rules
            if rule.source_capture is not None
        }
        claims: list[ByteClaim] = []
        for segment in self.segments:
            if segment.kind is SegmentKind.UNKNOWN:
                continue
            if segment.kind is SegmentKind.STRUCTURAL:
                disposition = ByteDisposition.STRUCTURAL
                rule_uid = "parser.structure"
                target_path = None
            elif segment.name in targets:
                disposition = ByteDisposition.MAPPED
                rule_uid = f"mapping.{segment.name}"
                target_path = targets[segment.name]
            else:
                disposition = ByteDisposition.IGNORED
                rule_uid = f"parser.capture.{segment.name}"
                target_path = None
            claims.append(
                ByteClaim.from_raw(
                    self.raw,
                    start=segment.start,
                    end=segment.end,
                    disposition=disposition,
                    rule_uid=rule_uid,
                    target_path=target_path,
                    transformation=(
                        next(
                            (
                                rule.transform.value
                                for rule in rules
                                if rule.source_capture == segment.name
                            ),
                            None,
                        )
                        if target_path is not None
                        else None
                    ),
                )
            )
        return claims


def decode_utf8(raw: bytes, *, field: str) -> str:
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ParseError(f"{field} is not valid UTF-8") from exc


def unescape(raw: bytes, *, field: str) -> str:
    output = bytearray()
    escaped = False
    translations = {ord("n"): ord("\n"), ord("r"): ord("\r")}
    for byte in raw:
        if escaped:
            output.append(translations.get(byte, byte))
            escaped = False
        elif byte == ord("\\"):
            escaped = True
        else:
            output.append(byte)
    if escaped:
        raise ParseError(f"{field} ends with an incomplete escape")
    return decode_utf8(bytes(output), field=field)
