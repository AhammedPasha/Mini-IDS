
from fastapi.testclient import TestClient

from backend.api.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "online"


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_alert_limit_is_respected():
    response = client.get("/api/v1/alerts?limit=5")

    assert response.status_code == 200
    data = response.json()
    assert data["count"] <= 5
    assert len(data["alerts"]) <= 5


def test_combined_alert_filters():
    response = client.get(
        "/api/v1/alerts",
        params={
            "severity": "medium",
            "detection_source": "flow",
            "limit": 5,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["count"] <= 5

    for alert in data["alerts"]:
        assert alert["severity"] == "medium"
        assert alert["detection_source"] == "flow"


def test_invalid_severity_is_rejected():
    response = client.get("/api/v1/alerts?severity=urgent")

    assert response.status_code == 422
