import pandas as pd
import pytest

from ids.behavior_detector import detect_repeated_connections


def sample_flows():
    return pd.DataFrame({
        "source_ip": ["192.168.1.10"] * 5,
        "destination_ip": ["192.168.1.20"] * 5,
        "packet_count": [2, 3, 1, 4, 2],
    })


def test_detects_repeated_connections():
    alerts = detect_repeated_connections(
        sample_flows(),
        connection_threshold=5,
    )
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "REPEATED_CONNECTION_ATTEMPTS"


def test_normal_connections_produce_no_alert():
    assert detect_repeated_connections(
        sample_flows(),
        connection_threshold=10,
    ) == []


def test_empty_flows():
    flows = pd.DataFrame(columns=[
        "source_ip", "destination_ip", "packet_count"
    ])
    assert detect_repeated_connections(flows) == []


def test_missing_columns():
    with pytest.raises(ValueError, match="Missing required columns"):
        detect_repeated_connections(pd.DataFrame({"source_ip": ["A"]}))


def test_invalid_threshold():
    with pytest.raises(ValueError):
        detect_repeated_connections(
            sample_flows(),
            connection_threshold=1,
        )