import base64

from httpx import ASGITransport, AsyncClient

from drishti.api.app import create_app


async def test_health_and_ingestion_contract() -> None:
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        health = await client.get("/health/live")
        assert health.json() == {"status": "ok"}

        body = {
            "tenant_id": "demo-org",
            "source_id": "router-01",
            "source_type": "router",
            "idempotency_key": "offset-1",
            "payload_base64": base64.b64encode(b"allow src=10.0.0.1").decode(),
        }
        response = await client.post("/v1/events", json=body)

    assert response.status_code == 202
    assert response.json()["status"] == "archived"
    assert response.json()["duplicate"] is False
    assert len(response.json()["raw_sha256"]) == 64


async def test_rejects_invalid_base64() -> None:
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/events",
            json={
                "tenant_id": "demo-org",
                "source_id": "router-01",
                "payload_base64": "not valid base64!!",
            },
        )

    assert response.status_code == 422
    assert "canonical base64" in response.json()["detail"]


async def test_validates_ocsf_against_pinned_contract() -> None:
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/ocsf/validate",
            json={
                "event": {
                    "activity_id": 1,
                    "category_uid": 4,
                    "class_uid": 4001,
                    "metadata": {"product": {"name": "Drishti"}, "version": "1.9.0"},
                    "severity_id": 1,
                    "src_endpoint": {"ip": "10.0.0.1", "uid": "10.0.0.1"},
                    "time": 1_798_000_000_000,
                    "type_uid": 400101,
                }
            },
        )

    assert response.status_code == 200
    assert response.json()["valid"] is True
    assert response.json()["class_name"] == "network_activity"
    assert response.json()["schema"]["ocsf_version"] == "1.9.0"
