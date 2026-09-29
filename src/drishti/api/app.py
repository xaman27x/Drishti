from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Request, status
from fastapi.responses import JSONResponse

from drishti.adapters.memory import InMemoryEventPublisher, InMemoryRawEvidenceStore
from drishti.api.schemas import (
    ErrorResponse,
    IngestEventRequest,
    IngestEventResponse,
    ValidateOcsfRequest,
    ValidateOcsfResponse,
)
from drishti.config import get_settings
from drishti.ocsf.catalog import OcsfCatalog, get_ocsf_catalog
from drishti.pipeline.ingestion import (
    IdempotencyConflictError,
    IngestionService,
    PayloadTooLargeError,
)


def _service_from_request(request: Request) -> IngestionService:
    service: IngestionService = request.app.state.ingestion_service
    return service


def create_app(
    ingestion_service: IngestionService | None = None,
    ocsf_catalog: OcsfCatalog | None = None,
    runtime: Any | None = None,
) -> FastAPI:
    settings = get_settings()
    from drishti.api.runtime_routes import router
    from drishti.runtime.service import Runtime

    rt = runtime
    if rt is None and settings.adapter_mode == "durable":
        rt = Runtime(settings)
    if rt is not None:
        ingestion_service = rt.ingestion
    elif ingestion_service is None:
        ingestion_service = IngestionService(
            evidence_store=InMemoryRawEvidenceStore(),
            publisher=InMemoryEventPublisher(),
            max_event_bytes=settings.max_event_bytes,
        )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if rt:
            await rt.start_api()
        try:
            yield
        finally:
            if rt:
                await rt.close()

    app = FastAPI(
        title="Drishti ULPF",
        version="0.4.0",
        description="Lossless universal log ingestion and preprocessing",
        lifespan=lifespan,
    )
    app.state.runtime = rt
    app.include_router(router)
    app.state.ingestion_service = ingestion_service
    app.state.ocsf_catalog = ocsf_catalog or get_ocsf_catalog()

    @app.exception_handler(PayloadTooLargeError)
    async def payload_too_large(_: Request, exc: PayloadTooLargeError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": str(exc)},
        )

    @app.exception_handler(IdempotencyConflictError)
    async def idempotency_conflict(_: Request, exc: IdempotencyConflictError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.get("/health/live", tags=["health"])
    async def liveness() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready", tags=["health"])
    async def readiness() -> JSONResponse:
        if rt is None:
            return JSONResponse({"status": "ready", "mode": "memory"})
        health = await rt.health()
        return JSONResponse(health, status_code=200 if health["status"] == "ready" else 503)

    @app.get("/health/dependencies", tags=["health"])
    async def dependencies() -> dict[str, Any]:
        return await rt.health() if rt else {"status": "ready", "mode": "memory"}

    @app.post(
        "/v1/events",
        response_model=IngestEventResponse,
        status_code=status.HTTP_202_ACCEPTED,
        responses={
            409: {"model": ErrorResponse},
            413: {"model": ErrorResponse},
            422: {"model": ErrorResponse},
        },
        tags=["ingestion"],
    )
    async def ingest_event(
        body: IngestEventRequest,
        service: Annotated[IngestionService, Depends(_service_from_request)],
    ) -> IngestEventResponse | JSONResponse:
        try:
            raw_bytes = body.decode_payload()
        except ValueError as exc:
            return JSONResponse(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                content={"detail": str(exc)},
            )

        receipt = await service.ingest(
            source=body.source(),
            raw_bytes=raw_bytes,
            idempotency_key=body.idempotency_key,
            observed_at=body.observed_at,
        )
        return IngestEventResponse(
            event_id=receipt.event_id,
            trace_id=receipt.trace_id,
            raw_sha256=receipt.raw_sha256,
            duplicate=receipt.duplicate,
        )

    @app.post(
        "/v1/ocsf/validate",
        response_model=ValidateOcsfResponse,
        tags=["ocsf"],
    )
    async def validate_ocsf(body: ValidateOcsfRequest, request: Request) -> ValidateOcsfResponse:
        catalog: OcsfCatalog = request.app.state.ocsf_catalog
        report = catalog.validate(body.event)
        return ValidateOcsfResponse.model_validate(report.model_dump())

    return app
