
import hmac
import os
from datetime import datetime, timezone
from typing import Literal

from dotenv import load_dotenv
from fastapi import (
    FastAPI,
    Header,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
)
from pydantic import BaseModel, Field

load_dotenv()

INTERNAL_API_TOKEN = os.getenv("IDS_INTERNAL_API_TOKEN")

class AlertPublishRequest(BaseModel):
    alert: dict = Field(..., description="Security alert to broadcast")


from backend.api.websocket_manager import alert_manager
from ids.database import get_alert_history

app = FastAPI(
    title="Network Intrusion Detection Platform API",
    description=(
        "Backend API for network traffic analysis, "
        "intrusion alerts, and monitoring."
    ),
    version="0.4.0",
)


@app.get("/", tags=["System"])
def root():
    return {
        "service": "Network Intrusion Detection Platform",
        "status": "online",
        "api_version": app.version,
        "docs": "/docs",
    }


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "ids-backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/v1/internal/alerts/publish", tags=["Internal"])
async def publish_alert(
    request: AlertPublishRequest,
    x_internal_api_token: str | None = Header(default=None),
):
    """Publish a trusted internal alert to connected WebSocket clients."""
    if not INTERNAL_API_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Internal alert publishing is not configured.",
        )

    if not x_internal_api_token or not hmac.compare_digest(
        x_internal_api_token,
        INTERNAL_API_TOKEN,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid internal API token.",
        )

    alert = request.alert
    event = {
        "type": "security_alert",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert": alert,
    }

    await alert_manager.broadcast(event)

    return {
        "status": "published",
        "message": "Alert broadcast requested.",
    }



@app.get("/api/v1/alerts", tags=["Security Alerts"])
def list_alerts(
    limit: int = Query(default=100, ge=1, le=500),
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    detection_source: Literal["packet", "flow"] | None = None,
):
    """Return recent stored alerts, optionally filtered."""
    alerts = get_alert_history(limit=500)

    if severity is not None:
        alerts = [
            alert for alert in alerts
            if (alert.get("severity") or "").lower() == severity
        ]

    if detection_source is not None:
        alerts = [
            alert for alert in alerts
            if alert.get("detection_source") == detection_source
        ]

    alerts = alerts[:limit]

    return {
        "count": len(alerts),
        "limit": limit,
        "filters": {
            "severity": severity,
            "detection_source": detection_source,
        },
        "alerts": alerts,
    }


@app.websocket("/ws/alerts")
async def alert_websocket(websocket: WebSocket):
    """Maintain a WebSocket connection for alert events."""
    await alert_manager.connect(websocket)

    try:
        await websocket.send_json({
            "type": "connection_established",
            "service": "ids-backend",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "Connected to the IDS alert event stream.",
        })

        while True:
            # Keep the connection alive while receiving client messages.
            await websocket.receive_text()

    except WebSocketDisconnect:
        pass

    finally:
        await alert_manager.disconnect(websocket)
