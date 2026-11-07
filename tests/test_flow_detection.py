
import pandas as pd
import pytest

from ids.flow_detection import detect_suspicious_flows


def sample_flows():
    return pd.DataFrame({
        "source_ip": ["10.0.0.1"],
        "destination_ip": ["10.0.0.2"],
        "source_port": [50000],
        "destination_port": [443],
        "protocol": ["TCP"],
        "packet_count": [1500],
        "total_bytes": [2_000_000],
        "duration_seconds": [4000.0],
        "packets_per_second": [150.0],
    })


def test_detects_high_volume_flow():
    alerts = detect_suspicious_flows(sample_flows())

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert "HIGH_VOLUME_FLOW" in rule_ids
    assert "HIGH_BYTE_VOLUME_FLOW" in rule_ids


def test_detects_high_packet_rate():
    alerts = detect_suspicious_flows(sample_flows())

    assert any(
        alert["rule_id"] == "HIGH_PACKET_RATE_FLOW"
        for alert in alerts
    )


def test_detects_long_lived_flow():
    alerts = detect_suspicious_flows(sample_flows())

    assert any(
        alert["rule_id"] == "LONG_LIVED_FLOW"
        for alert in alerts
    )


def test_normal_flow_does_not_trigger_default_rules():
    flows = sample_flows()
    flows.loc[0, "packet_count"] = 10
    flows.loc[0, "total_bytes"] = 5000
    flows.loc[0, "duration_seconds"] = 10
    flows.loc[0, "packets_per_second"] = 1

    assert detect_suspicious_flows(flows) == []


def test_empty_flow_table_returns_no_alerts():
    flows = sample_flows().iloc[0:0]

    assert detect_suspicious_flows(flows) == []


def test_missing_column_raises_error():
    flows = sample_flows().drop(columns=["packet_count"])

    with pytest.raises(ValueError, match="packet_count"):
        detect_suspicious_flows(flows)


def test_invalid_threshold_raises_error():
    with pytest.raises(ValueError, match="packet_threshold"):
        detect_suspicious_flows(
            sample_flows(),
            packet_threshold=0,
        )
