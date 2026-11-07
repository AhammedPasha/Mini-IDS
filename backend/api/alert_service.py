
import os

import httpx
from dotenv import load_dotenv

from ids.database import save_alerts_returning


load_dotenv()

API_BASE_URL = os.getenv("IDS_API_BASE_URL", "http://127.0.0.1:8000")
INTERNAL_API_TOKEN = os.getenv("IDS_INTERNAL_API_TOKEN")


async def save_and_broadcast_alerts(
    alerts: list[dict],
    capture_name: str = "",
    analysis_id: str | None = None,
    detection_source: str = "packet",
) -> int:
    """Save new alerts and publish them through the running FastAPI server."""
    inserted_alerts = save_alerts_returning(
        alerts=alerts,
        capture_name=capture_name,
        analysis_id=analysis_id,
        detection_source=detection_source,
    )

    if not inserted_alerts:
        return 0

    if not INTERNAL_API_TOKEN:
        raise RuntimeError("IDS_INTERNAL_API_TOKEN is not configured.")

    headers = {"X-Internal-API-Token": INTERNAL_API_TOKEN}
    published_count = 0

    async with httpx.AsyncClient(timeout=5.0) as client:
        for alert in inserted_alerts:
            response = await client.post(
                f"{API_BASE_URL}/api/v1/internal/alerts/publish",
                headers=headers,
                json={"alert": alert},
            )
            response.raise_for_status()
            published_count += 1

    return published_count
