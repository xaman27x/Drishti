from __future__ import annotations

from drishti.parsers.common import ParseError, ParseResult, Segment, SegmentKind, decode_utf8
from drishti.parsers.models import ParserFormat
from drishti.parsers.tokenize import tokenize_key_values


class Rfc5424Parser:
    format = ParserFormat.RFC5424

    def parse(self, raw: bytes) -> ParseResult:
        if not raw.startswith(b"<"):
            raise ParseError("RFC5424 event must start with '<PRI>'")
        close = raw.find(b">", 1, 5)
        if close < 0:
            raise ParseError("RFC5424 PRI is missing its closing delimiter")
        pri_raw = raw[1:close]
        if not pri_raw.isdigit() or not 0 <= int(pri_raw) <= 191:
            raise ParseError("RFC5424 PRI must be an integer from 0 through 191")

        segments = [
            Segment(0, 1, SegmentKind.STRUCTURAL),
            Segment(1, close, SegmentKind.CAPTURE, "pri", pri_raw.decode("ascii")),
            Segment(close, close + 1, SegmentKind.STRUCTURAL),
        ]
        cursor = close + 1

        def token(name: str) -> None:
            nonlocal cursor
            end = raw.find(b" ", cursor)
            if end < 0 or end == cursor:
                raise ParseError(f"RFC5424 header field {name} is missing")
            value_raw = raw[cursor:end]
            segments.append(
                Segment(cursor, end, SegmentKind.CAPTURE, name, decode_utf8(value_raw, field=name))
            )
            segments.append(Segment(end, end + 1, SegmentKind.STRUCTURAL))
            cursor = end + 1

        token("version")
        if int(segments[3].value or "0") < 1:
            raise ParseError("RFC5424 version must be positive")
        token("timestamp")
        token("hostname")
        token("app_name")
        token("process_id")
        token("message_id")

        structured_start = cursor
        if cursor >= len(raw):
            raise ParseError("RFC5424 structured data is missing")
        if raw[cursor] == ord("-"):
            cursor += 1
        elif raw[cursor] == ord("["):
            cursor = self._scan_structured_data(raw, cursor)
        else:
            raise ParseError("RFC5424 structured data must be '-' or bracketed data")
        segments.append(
            Segment(
                structured_start,
                cursor,
                SegmentKind.CAPTURE,
                "structured_data",
                decode_utf8(raw[structured_start:cursor], field="structured_data"),
            )
        )

        if cursor < len(raw):
            if raw[cursor] != ord(" "):
                raise ParseError("RFC5424 message must follow a single space")
            segments.append(Segment(cursor, cursor + 1, SegmentKind.STRUCTURAL))
            cursor += 1
            if cursor < len(raw):
                segments.extend(tokenize_key_values(raw, start=cursor, prefix="msg"))
        return ParseResult(self.format, raw, tuple(segments))

    @staticmethod
    def _scan_structured_data(raw: bytes, start: int) -> int:
        cursor = start
        while cursor < len(raw) and raw[cursor] == ord("["):
            cursor += 1
            quoted = False
            escaped = False
            while cursor < len(raw):
                byte = raw[cursor]
                if escaped:
                    escaped = False
                elif byte == ord("\\") and quoted:
                    escaped = True
                elif byte == ord('"'):
                    quoted = not quoted
                elif byte == ord("]") and not quoted:
                    cursor += 1
                    break
                cursor += 1
            else:
                raise ParseError("RFC5424 structured data is not terminated")
            if quoted:
                raise ParseError("RFC5424 structured data contains an unterminated quote")
        return cursor
