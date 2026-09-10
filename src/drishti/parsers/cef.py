from __future__ import annotations

from drishti.parsers.common import ParseError, ParseResult, Segment, SegmentKind, unescape
from drishti.parsers.models import ParserFormat
from drishti.parsers.tokenize import tokenize_key_values


class CefParser:
    format = ParserFormat.CEF
    _HEADER_NAMES = (
        "cef.version",
        "device.vendor",
        "device.product",
        "device.version",
        "signature_id",
        "name",
        "severity",
    )

    def parse(self, raw: bytes) -> ParseResult:
        if not raw.startswith(b"CEF:"):
            raise ParseError("CEF event must start with 'CEF:'")
        segments: list[Segment] = [Segment(0, 4, SegmentKind.STRUCTURAL)]
        cursor = 4
        for name in self._HEADER_NAMES:
            end = self._find_unescaped_pipe(raw, cursor)
            if end < 0:
                raise ParseError(f"CEF header field {name} is missing its delimiter")
            if end == cursor:
                raise ParseError(f"CEF header field {name} must not be empty")
            value_raw = raw[cursor:end]
            segments.append(
                Segment(cursor, end, SegmentKind.CAPTURE, name, unescape(value_raw, field=name))
            )
            segments.append(Segment(end, end + 1, SegmentKind.STRUCTURAL))
            cursor = end + 1

        if cursor < len(raw):
            segments.extend(tokenize_key_values(raw, start=cursor, prefix="ext"))
        return ParseResult(self.format, raw, tuple(segments))

    @staticmethod
    def _find_unescaped_pipe(raw: bytes, start: int) -> int:
        escaped = False
        for index in range(start, len(raw)):
            byte = raw[index]
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord("|"):
                return index
        return -1
