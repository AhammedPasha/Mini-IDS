
import asyncio
import json
import os

import httpx
import websockets
from dotenv import load_dotenv

load_dotenv()

async def main():
    token = os.getenv("IDS_INTERNAL_API_TOKEN")

    if not token:
        print("ERROR: IDS_INTERNAL_API_TOKEN is missing from .env")
        return

    uri = "ws://127.0.0.1:8000/ws/alerts"

    async with websockets.connect(uri) as websocket:
        welcome = json.loads(await websocket.recv())
        print("WebSocket connected:", welcome["type"])

        alert = {
            "rule_id": "LIVE_INTEGRATION_TEST",
            "severity": "medium",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.20",
            "evidence": "Real-time live WebSocket delivery test"
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                "http://127.0.0.1:8000/api/v1/internal/alerts/publish",
                headers={"X-Internal-API-Token": token},
                json={"alert": alert}
            )

            response.raise_for_status()
            print("HTTP publishing:", response.json()["status"])

        message = await asyncio.wait_for(websocket.recv(), timeout=10)
        event = json.loads(message)

        print("\nReceived live event:")
        print(json.dumps(event, indent=4))

        assert event["type"] == "security_alert"
        assert event["alert"]["rule_id"] == "LIVE_INTEGRATION_TEST"

        print("\nSUCCESS: Live alert delivery verified!")

asyncio.run(main())
