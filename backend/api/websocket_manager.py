
import asyncio
from fastapi import WebSocket


class AlertConnectionManager:
    """Manage connected WebSocket clients for IDS alert events."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()

        async with self._lock:
            self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast(self, event: dict) -> None:
        async with self._lock:
            connections = list(self.active_connections)

        disconnected = []

        for websocket in connections:
            try:
                await websocket.send_json(event)
            except Exception:
                disconnected.append(websocket)

        for websocket in disconnected:
            await self.disconnect(websocket)


alert_manager = AlertConnectionManager()
