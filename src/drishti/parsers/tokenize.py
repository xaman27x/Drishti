from __future__ import annotations

import re

from drishti.parsers.common import ParseError, Segment, SegmentKind, unescape

KEY_PATTERN = re.compile(rb"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


def tokenize_key_values(raw: bytes, *, start: int, prefix: str) -> list[Segment]:
    """Tokenize space-delimited key/value data without executing source-controlled regex."""
    segments: list[Segment] = []
    cursor = start
    while cursor < len(raw):
        if raw[cursor] == ord(" "):
            end = cursor + 1
            while end < len(raw) and raw[end] == ord(" "):
                end += 1
            segments.append(Segment(cursor, end, SegmentKind.STRUCTURAL))
            cursor = end
            continue

        key_start = cursor
        while cursor < len(raw) and raw[cursor] not in (ord("="), ord(" ")):
            cursor += 1
        if cursor >= len(raw) or raw[cursor] != ord("="):
            end = raw.find(b" ", key_start)
            end = len(raw) if end < 0 else end
            segments.append(Segment(key_start, end, SegmentKind.UNKNOWN))
            cursor = end
            continue

        key = raw[key_start:cursor]
        if not KEY_PATTERN.fullmatch(key):
            raise ParseError("key/value message contains an invalid key")
        capture_name = f"{prefix}.{key.decode('ascii')}"
        segments.append(Segment(key_start, cursor + 1, SegmentKind.STRUCTURAL))
        cursor += 1
        if cursor >= len(raw) or raw[cursor] == ord(" "):
            continue

        if raw[cursor] == ord('"'):
            segments.append(Segment(cursor, cursor + 1, SegmentKind.STRUCTURAL))
            cursor += 1
            value_start = cursor
            escaped = False
            while cursor < len(raw):
                byte = raw[cursor]
                if escaped:
                    escaped = False
                elif byte == ord("\\"):
                    escaped = True
                elif byte == ord('"'):
                    break
                cursor += 1
            if cursor >= len(raw):
                raise ParseError(f"unterminated quoted value for {capture_name}")
            if cursor > value_start:
                value_raw = raw[value_start:cursor]
                segments.append(
                    Segment(
                        value_start,
                        cursor,
                        SegmentKind.CAPTURE,
                        capture_name,
                        unescape(value_raw, field=capture_name),
                    )
                )
            segments.append(Segment(cursor, cursor + 1, SegmentKind.STRUCTURAL))
            cursor += 1
            if cursor < len(raw) and raw[cursor] != ord(" "):
                raise ParseError(f"quoted value for {capture_name} is not space terminated")
            continue

        value_start = cursor
        while cursor < len(raw) and raw[cursor] != ord(" "):
            cursor += 1
        value_raw = raw[value_start:cursor]
        segments.append(
            Segment(
                value_start,
                cursor,
                SegmentKind.CAPTURE,
                capture_name,
                unescape(value_raw, field=capture_name),
            )
        )
    return segments
