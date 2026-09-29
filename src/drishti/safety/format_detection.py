from __future__ import annotations

import hashlib
import hmac
import math
from collections import Counter, deque
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

FEATURE_NAMES = (
    "length_bucket",
    "equals_per_kb",
    "pipes_per_kb",
    "spaces_per_kb",
    "brackets_per_kb",
    "quotes_per_kb",
    "colons_per_kb",
    "control_bytes_per_kb",
)


class FormatFingerprint(BaseModel):
    """Privacy-preserving structural identity; it contains no log values."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    fingerprint_version: str = "drishti.format-fingerprint/v1"
    source_key: str
    fingerprint_hmac: str = Field(pattern=r"^[a-f0-9]{64}$")
    features: tuple[int, ...] = Field(min_length=len(FEATURE_NAMES), max_length=len(FEATURE_NAMES))


class FormatFingerprinter:
    """Produces comparable HMAC fingerprints over value-redacted byte shapes."""

    def __init__(self, sharing_key: bytes) -> None:
        if len(sharing_key) < 16:
            raise ValueError("format-sharing key must contain at least 128 bits")
        self._key = sharing_key

    def fingerprint(self, *, source_key: str, raw: bytes) -> FormatFingerprint:
        shape = self._shape(raw)
        digest = hmac.new(self._key, shape, hashlib.sha256).hexdigest()
        return FormatFingerprint(
            source_key=source_key,
            fingerprint_hmac=digest,
            features=self.feature_vector(raw),
        )

    @staticmethod
    def feature_vector(raw: bytes) -> tuple[int, ...]:
        size = max(1, len(raw))

        def per_kb(byte_values: set[int]) -> int:
            return round(sum(byte in byte_values for byte in raw) * 1_000 / size)

        return (
            min(31, int(math.log2(size + 1))),
            per_kb({ord("=")}),
            per_kb({ord("|")}),
            per_kb({ord(" "), ord("\t")}),
            per_kb({ord("["), ord("]"), ord("{"), ord("}")}),
            per_kb({ord('"'), ord("'")}),
            per_kb({ord(":")}),
            per_kb(set(range(0, 32)) - {9, 10, 13}),
        )

    @staticmethod
    def _shape(raw: bytes) -> bytes:
        """Redact values into character classes and run-length compress the result."""

        classes = bytearray()
        previous: int | None = None
        run = 0
        for byte in raw:
            if 65 <= byte <= 90 or 97 <= byte <= 122:
                current = ord("A")
            elif 48 <= byte <= 57:
                current = ord("0")
            elif byte in {ord(" "), ord("\t"), ord("\n"), ord("\r")}:
                current = ord("_")
            elif 32 <= byte <= 126:
                current = byte
            else:
                current = ord("?")
            if current == previous:
                run += 1
                continue
            if previous is not None:
                classes.extend((previous, min(run, 255)))
            previous = current
            run = 1
        if previous is not None:
            classes.extend((previous, min(run, 255)))
        return bytes(classes)


class DriftStatus(StrEnum):
    LEARNING = "learning"
    STABLE = "stable"
    WARNING = "warning"
    QUARANTINE = "quarantine"


class DriftDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: UUID
    source_key: str
    observed_at: datetime
    status: DriftStatus
    fingerprint: FormatFingerprint
    js_divergence: float = Field(ge=0, le=1)
    feature_distance: float = Field(ge=0)
    baseline_events: int = Field(ge=0)
    window_events: int = Field(ge=0)
    reason: str


class FormatChangeDetector:
    """Detects structural changes in a source's log format without retaining values."""

    def __init__(
        self,
        *,
        source_key: str,
        fingerprinter: FormatFingerprinter,
        baseline_size: int = 32,
        window_size: int = 16,
        warning_jsd: float = 0.25,
        quarantine_jsd: float = 0.60,
        warning_feature_distance: float = 0.15,
        quarantine_feature_distance: float = 0.35,
    ) -> None:
        if baseline_size < 4 or window_size < 2:
            raise ValueError("drift windows are too small for a meaningful decision")
        if not 0 <= warning_jsd < quarantine_jsd <= 1:
            raise ValueError("Jensen-Shannon thresholds are invalid")
        self.source_key = source_key
        self._fingerprinter = fingerprinter
        self._baseline_size = baseline_size
        self._window_size = window_size
        self._warning_jsd = warning_jsd
        self._quarantine_jsd = quarantine_jsd
        self._warning_feature_distance = warning_feature_distance
        self._quarantine_feature_distance = quarantine_feature_distance
        self._baseline: list[FormatFingerprint] = []
        self._window: deque[FormatFingerprint] = deque(maxlen=window_size)

    def snapshot(self) -> dict[str, object]:
        return {
            "baseline": [item.model_dump(mode="json") for item in self._baseline],
            "window": [item.model_dump(mode="json") for item in self._window],
        }

    def restore(self, snapshot: dict[str, object]) -> None:
        baseline = snapshot.get("baseline", [])
        window = snapshot.get("window", [])
        if not isinstance(baseline, list) or not isinstance(window, list):
            raise ValueError("invalid detector snapshot")
        self._baseline = [FormatFingerprint.model_validate(item) for item in baseline]
        self._window = deque(
            (FormatFingerprint.model_validate(item) for item in window), maxlen=self._window_size
        )

    def observe(self, *, event_id: UUID, raw: bytes) -> DriftDecision:
        fingerprint = self._fingerprinter.fingerprint(source_key=self.source_key, raw=raw)
        if len(self._baseline) < self._baseline_size:
            self._baseline.append(fingerprint)
            return self._decision(
                event_id=event_id,
                fingerprint=fingerprint,
                status=DriftStatus.LEARNING,
                jsd=0,
                distance=0,
                reason=f"learning trusted baseline ({len(self._baseline)}/{self._baseline_size})",
            )

        self._window.append(fingerprint)
        jsd = self._jensen_shannon(self._baseline, list(self._window))
        distance = self._feature_distance(self._baseline, list(self._window))
        if len(self._window) < self._window_size:
            status = DriftStatus.LEARNING
            reason = f"filling observation window ({len(self._window)}/{self._window_size})"
        elif jsd >= self._quarantine_jsd or distance >= self._quarantine_feature_distance:
            status = DriftStatus.QUARANTINE
            reason = "log format change exceeds the quarantine threshold"
        elif jsd >= self._warning_jsd or distance >= self._warning_feature_distance:
            status = DriftStatus.WARNING
            reason = "log format change requires operator review"
        else:
            status = DriftStatus.STABLE
            reason = "log format remains within the learned baseline"
        return self._decision(
            event_id=event_id,
            fingerprint=fingerprint,
            status=status,
            jsd=jsd,
            distance=distance,
            reason=reason,
        )

    def _decision(
        self,
        *,
        event_id: UUID,
        fingerprint: FormatFingerprint,
        status: DriftStatus,
        jsd: float,
        distance: float,
        reason: str,
    ) -> DriftDecision:
        return DriftDecision(
            event_id=event_id,
            source_key=self.source_key,
            observed_at=datetime.now(UTC),
            status=status,
            fingerprint=fingerprint,
            js_divergence=round(jsd, 6),
            feature_distance=round(distance, 6),
            baseline_events=len(self._baseline),
            window_events=len(self._window),
            reason=reason,
        )

    @staticmethod
    def _jensen_shannon(
        baseline: list[FormatFingerprint], window: list[FormatFingerprint]
    ) -> float:
        if not baseline or not window:
            return 0.0
        left = Counter(item.fingerprint_hmac for item in baseline)
        right = Counter(item.fingerprint_hmac for item in window)
        keys = set(left) | set(right)
        p = {key: left[key] / len(baseline) for key in keys}
        q = {key: right[key] / len(window) for key in keys}
        midpoint = {key: (p[key] + q[key]) / 2 for key in keys}

        def divergence(values: dict[str, float]) -> float:
            return sum(
                probability * math.log2(probability / midpoint[key])
                for key, probability in values.items()
                if probability > 0
            )

        return min(1.0, (divergence(p) + divergence(q)) / 2)

    @staticmethod
    def _feature_distance(
        baseline: list[FormatFingerprint], window: list[FormatFingerprint]
    ) -> float:
        if not baseline or not window:
            return 0.0

        def centroid(values: list[FormatFingerprint]) -> tuple[float, ...]:
            return tuple(
                sum(item.features[index] for item in values) / len(values)
                for index in range(len(FEATURE_NAMES))
            )

        base = centroid(baseline)
        current = centroid(window)
        distances = [
            abs(left - right) / max(1.0, abs(left))
            for left, right in zip(base, current, strict=True)
        ]
        return sum(min(1.0, value) for value in distances) / len(distances)
