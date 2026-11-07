
from datetime import datetime, timezone

from backend.api.websocket_manager import alert_manager


async def broadcast_alert(alert: dict) -> None:
    """Broadcast an IDS alert event to connected WebSocket clients."""
    event = {
        "type": "security_alert",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert": alert,
    }

    await alert_manager.broadcast(event)
