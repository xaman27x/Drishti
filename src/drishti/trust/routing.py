from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from drishti.domain.events import RawEvent
from drishti.trust.dialect import DialectDriftSentinel, DriftDecision, DriftStatus


class TrustRoute(StrEnum):
    ACTIVE_PARSER = "active-parser"
    REVIEW_MIRROR = "review-mirror"
    QUARANTINE = "quarantine"


class RoutingReceipt(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: DriftDecision
    routes: tuple[TrustRoute, ...]


class TrustRoutePublisher(Protocol):
    async def publish_active(self, event: RawEvent, decision: DriftDecision) -> None: ...

    async def publish_review(self, event: RawEvent, decision: DriftDecision) -> None: ...

    async def publish_quarantine(self, event: RawEvent, decision: DriftDecision) -> None: ...


class AdaptiveTrustRouter:
    """Turns drift decisions into explicit, lossless downstream routing."""

    def __init__(
        self,
        *,
        sentinel: DialectDriftSentinel,
        publisher: TrustRoutePublisher,
    ) -> None:
        self._sentinel = sentinel
        self._publisher = publisher

    async def route(self, event: RawEvent) -> RoutingReceipt:
        decision = self._sentinel.observe(event_id=event.event_id, raw=event.raw_bytes)
        routes: tuple[TrustRoute, ...]
        if decision.status is DriftStatus.QUARANTINE:
            await self._publisher.publish_quarantine(event, decision)
            routes = (TrustRoute.QUARANTINE,)
        elif decision.status is DriftStatus.WARNING:
            await self._publisher.publish_active(event, decision)
            await self._publisher.publish_review(event, decision)
            routes = (TrustRoute.ACTIVE_PARSER, TrustRoute.REVIEW_MIRROR)
        else:
            await self._publisher.publish_active(event, decision)
            routes = (TrustRoute.ACTIVE_PARSER,)
        return RoutingReceipt(decision=decision, routes=routes)
