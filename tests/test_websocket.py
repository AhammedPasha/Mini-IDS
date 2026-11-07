
from fastapi.testclient import TestClient

from backend.api.main import app

client = TestClient(app)


def test_alert_websocket_connection():
    with client.websocket_connect("/ws/alerts") as websocket:
        message = websocket.receive_json()

        assert message["type"] == "connection_established"
        assert message["service"] == "ids-backend"
        assert "timestamp" in message
