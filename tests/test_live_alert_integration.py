
from fastapi.testclient import TestClient

from backend.api.main import app, INTERNAL_API_TOKEN

client = TestClient(app)


def test_http_publish_reaches_websocket_client():
    assert INTERNAL_API_TOKEN, "Internal API token is not configured."

    alert = {
        "rule_id": "INTEGRATION_TEST",
        "severity": "medium",
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.20",
        "evidence": "Live WebSocket integration test",
    }

    with client.websocket_connect("/ws/alerts") as websocket:
        welcome = websocket.receive_json()
        assert welcome["type"] == "connection_established"

        response = client.post(
            "/api/v1/internal/alerts/publish",
            headers={
                "X-Internal-API-Token": INTERNAL_API_TOKEN
            },
            json={"alert": alert},
        )

        assert response.status_code == 200
        assert response.json()["status"] == "published"

        event = websocket.receive_json()

        assert event["type"] == "security_alert"
        assert event["alert"]["rule_id"] == "INTEGRATION_TEST"
        assert event["alert"]["evidence"] == (
            "Live WebSocket integration test"
        )
