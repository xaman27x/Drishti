from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from drishti.domain.events import RawEvent
from drishti.safety.format_detection import DriftDecision, DriftStatus, FormatChangeDetector


class ProcessingRoute(StrEnum):
    ACTIVE_PARSER = "active-parser"
    REVIEW_MIRROR = "review-mirror"
    QUARANTINE = "quarantine"


class RoutingReceipt(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: DriftDecision
    routes: tuple[ProcessingRoute, ...]


class RoutePublisher(Protocol):
    async def publish_active(self, event: RawEvent, decision: DriftDecision) -> None: ...

    async def publish_review(self, event: RawEvent, decision: DriftDecision) -> None: ...

    async def publish_quarantine(self, event: RawEvent, decision: DriftDecision) -> None: ...


class FormatAwareRouter:
    """Routes changed formats for review without dropping raw evidence."""

    def __init__(
        self,
        *,
        detector: FormatChangeDetector,
        publisher: RoutePublisher,
    ) -> None:
        self._detector = detector
        self._publisher = publisher

    async def route(self, event: RawEvent) -> RoutingReceipt:
        decision = self._detector.observe(event_id=event.event_id, raw=event.raw_bytes)
        routes: tuple[ProcessingRoute, ...]
        if decision.status is DriftStatus.QUARANTINE:
            await self._publisher.publish_quarantine(event, decision)
            routes = (ProcessingRoute.QUARANTINE,)
        elif decision.status is DriftStatus.WARNING:
            await self._publisher.publish_active(event, decision)
            await self._publisher.publish_review(event, decision)
            routes = (ProcessingRoute.ACTIVE_PARSER, ProcessingRoute.REVIEW_MIRROR)
        else:
            await self._publisher.publish_active(event, decision)
            routes = (ProcessingRoute.ACTIVE_PARSER,)
        return RoutingReceipt(decision=decision, routes=routes)
