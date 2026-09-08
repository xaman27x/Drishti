import hashlib

import pytest

from drishti.adapters.memory import InMemoryEventPublisher, InMemoryRawEvidenceStore
from drishti.domain.events import SourceRef
from drishti.pipeline.ingestion import IdempotencyConflictError, IngestionService


@pytest.fixture
def source() -> SourceRef:
    return SourceRef(tenant_id="ntro-demo", source_id="edge-fw-01", source_type="firewall")


@pytest.fixture
def components() -> tuple[IngestionService, InMemoryRawEvidenceStore, InMemoryEventPublisher]:
    store = InMemoryRawEvidenceStore()
    publisher = InMemoryEventPublisher()
    service = IngestionService(evidence_store=store, publisher=publisher, max_event_bytes=1024)
    return service, store, publisher


async def test_archives_exact_bytes_before_publication(
    components: tuple[IngestionService, InMemoryRawEvidenceStore, InMemoryEventPublisher],
    source: SourceRef,
) -> None:
    service, store, publisher = components
    raw = b"<134>1 2026-09-26T12:34:56Z edge-fw deny src=10.0.0.4"

    receipt = await service.ingest(source=source, raw_bytes=raw, idempotency_key="sequence-42")

    archived = await store.get(receipt.event_id)
    assert archived is not None
    assert archived.raw_bytes == raw
    assert archived.raw_sha256 == hashlib.sha256(raw).hexdigest()
    assert archived.verify_integrity()
    assert publisher.published == [archived]


async def test_retry_is_idempotent_and_not_published_twice(
    components: tuple[IngestionService, InMemoryRawEvidenceStore, InMemoryEventPublisher],
    source: SourceRef,
) -> None:
    service, _, publisher = components
    kwargs = {"source": source, "raw_bytes": b"same", "idempotency_key": "device-offset-9"}

    first = await service.ingest(**kwargs)
    retry = await service.ingest(**kwargs)

    assert retry.event_id == first.event_id
    assert retry.duplicate is True
    assert len(publisher.published) == 1


async def test_rejects_idempotency_key_reuse_for_different_payloads(
    components: tuple[IngestionService, InMemoryRawEvidenceStore, InMemoryEventPublisher],
    source: SourceRef,
) -> None:
    service, _, _ = components
    await service.ingest(source=source, raw_bytes=b"first", idempotency_key="same-key")

    with pytest.raises(IdempotencyConflictError):
        await service.ingest(source=source, raw_bytes=b"different", idempotency_key="same-key")
