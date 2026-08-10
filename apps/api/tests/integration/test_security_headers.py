from fastapi.testclient import TestClient

from app.main import app


def test_security_headers_are_present() -> None:
    client = TestClient(app)

    response = client.get("/health")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
