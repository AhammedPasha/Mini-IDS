
import asyncio

from fastapi.testclient import TestClient

from backend.api.main import app
from backend.api.websocket_manager import alert_manager
from backend.api.alert_broadcaster import broadcast_alert


client = TestClient(app)


def test_broadcast_alert_reaches_connected_client():
    test_alert = {
        "alert_type": "PORT_SCAN_SUSPECTED",
        "severity": "medium",
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.20",
        "description": "Test alert for WebSocket broadcasting",
    }

    with client.websocket_connect("/ws/alerts") as websocket:
        # Read the initial connection message first.
        welcome = websocket.receive_json()
        assert welcome["type"] == "connection_established"

        # Broadcast an event while this client is connected.
        asyncio.run(broadcast_alert(test_alert))

        event = websocket.receive_json()

        assert event["type"] == "security_alert"
        assert event["alert"] == test_alert
        assert "timestamp" in event


def test_broadcast_with_no_clients_does_not_fail():
    # Broadcasting without connected clients should be safe.
    asyncio.run(
        alert_manager.broadcast({
            "type": "security_alert",
            "alert": {"alert_type": "TEST"},
        })
    )
