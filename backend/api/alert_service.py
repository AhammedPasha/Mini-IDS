
import os

import httpx
from dotenv import load_dotenv

from ids.database import save_alerts_returning


load_dotenv()


def get_config_value(key: str, default: str | None = None):
    """Read configuration from environment variables or Streamlit secrets."""

    value = os.getenv(key)

    if value:
        return value

    try:
        import streamlit as st
        value = st.secrets.get(key)
        if value:
            return str(value)
    except Exception:
        pass

    return default


API_BASE_URL = get_config_value(
    "IDS_API_BASE_URL",
    "http://127.0.0.1:8000"
).rstrip("/")

INTERNAL_API_TOKEN = get_config_value("IDS_INTERNAL_API_TOKEN")


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
