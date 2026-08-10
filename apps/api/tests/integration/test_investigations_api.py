from fastapi.testclient import TestClient

from app.main import app


def test_investigation_endpoint_returns_unified_json() -> None:
    client = TestClient(app)

    response = client.post("/api/v1/investigations", json={"ioc": "8.8.8.8"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["ioc"]["type"] == "ipv4"
    assert payload["modules"]["reputation"]
    assert payload["modules"]["geolocation"]
    assert payload["modules"]["relationship_graph"]["nodes"]
    assert payload["mappings"]["mitre_attack"]


def test_investigation_endpoint_rejects_invalid_ioc_without_quota_side_effect() -> None:
    client = TestClient(app)

    response = client.post("/api/v1/investigations", json={"ioc": "not an ioc"})

    assert response.status_code == 422
    assert response.json()["detail"] == "Unsupported or malformed IOC."
