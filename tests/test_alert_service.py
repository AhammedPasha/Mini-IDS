
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from backend.api.alert_service import save_and_broadcast_alerts


def test_new_alerts_are_broadcast():
    alert = {
        "rule_id": "PORT_SCAN_SUSPECTED",
        "severity": "medium",
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.20",
        "evidence": "Test port scan alert",
    }

    saved_record = {
        "id": 101,
        "analysis_id": "test-analysis",
        "detection_source": "packet",
        "capture_name": "test.pcap",
        **alert,
    }

    async def run_test():
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response

        with (
            patch(
                "backend.api.alert_service.save_alerts_returning",
                return_value=[saved_record],
            ) as save_mock,
            patch(
                "backend.api.alert_service.httpx.AsyncClient"
            ) as client_class,
        ):
            client_class.return_value.__aenter__.return_value = mock_client

            with patch(
                "backend.api.alert_service.INTERNAL_API_TOKEN",
                "test-token",
            ), patch(
                "backend.api.alert_service.API_BASE_URL",
                "http://127.0.0.1:8000",
            ):
                count = await save_and_broadcast_alerts(
                    alerts=[alert],
                    capture_name="test.pcap",
                    analysis_id="test-analysis",
                    detection_source="packet",
                )

        assert count == 1
        save_mock.assert_called_once()
        mock_client.post.assert_awaited_once_with(
            "http://127.0.0.1:8000/api/v1/internal/alerts/publish",
            headers={"X-Internal-API-Token": "test-token"},
            json={"alert": saved_record},
        )
        mock_response.raise_for_status.assert_called_once()

    asyncio.run(run_test())


def test_duplicate_alerts_are_not_broadcast():
    alert = {
        "rule_id": "PORT_SCAN_SUSPECTED",
        "severity": "medium",
        "evidence": "Duplicate test alert",
    }

    async def run_test():
        with (
            patch(
                "backend.api.alert_service.save_alerts_returning",
                return_value=[],
            ),
            patch(
                "backend.api.alert_service.httpx.AsyncClient"
            ) as client_class,
        ):
            count = await save_and_broadcast_alerts(
                alerts=[alert],
                analysis_id="test-analysis",
            )

        assert count == 0
        client_class.assert_not_called()

    asyncio.run(run_test())
