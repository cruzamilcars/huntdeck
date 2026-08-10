from fastapi.testclient import TestClient

from app.main import app

ALLOWED_ORIGIN = "http://localhost:3000"
DISALLOWED_ORIGIN = "http://evil.example.com"


def test_preflight_from_allowed_origin_succeeds() -> None:
    client = TestClient(app)

    response = client.options(
        "/api/v1/investigations",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ALLOWED_ORIGIN
    assert "POST" in response.headers["access-control-allow-methods"]


def test_preflight_from_disallowed_origin_is_rejected() -> None:
    client = TestClient(app)

    response = client.options(
        "/api/v1/investigations",
        headers={
            "Origin": DISALLOWED_ORIGIN,
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 400


def test_actual_request_from_allowed_origin_has_cors_header() -> None:
    client = TestClient(app)

    response = client.post(
        "/api/v1/investigations",
        json={"ioc": "8.8.8.8"},
        headers={"Origin": ALLOWED_ORIGIN},
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ALLOWED_ORIGIN