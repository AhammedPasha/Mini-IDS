
import asyncio
import os

import httpx
from dotenv import load_dotenv

load_dotenv()

async def main():
    token = os.getenv("IDS_INTERNAL_API_TOKEN")
    if not token:
        print("ERROR: API token is not configured.")
        return

    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(
            "http://127.0.0.1:8000/api/v1/internal/alerts/publish",
            headers={"X-Internal-API-Token": token},
            json={
                "alert": {
                    "rule_id": "HTTP_PATH_TEST",
                    "severity": "low",
                    "evidence": "Temporary connectivity test",
                }
            },
        )

        print("Status:", response.status_code)
        print("Response:", response.json())

asyncio.run(main())
