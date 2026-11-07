
import pandas as pd
import pytest

from ids.anomaly_detector import detect_statistical_anomalies


def sample_flows():
    return pd.DataFrame({
        "source_ip": ["A", "B", "C", "D", "E"],
        "destination_ip": ["X"] * 5,
        "packets_per_second": [10, 12, 11, 9, 500],
        "bytes_per_second": [100, 120, 110, 90, 5000],
    })


def test_detects_high_packet_rate_anomaly():
    alerts = detect_statistical_anomalies(sample_flows())
    assert any(a["rule_id"] == "HIGH_PACKET_RATE_ANOMALY" for a in alerts)


def test_detects_high_bandwidth_anomaly():
    alerts = detect_statistical_anomalies(sample_flows())
    assert any(a["rule_id"] == "HIGH_BANDWIDTH_ANOMALY" for a in alerts)


def test_normal_traffic_produces_no_anomalies():
    flows = sample_flows()
    flows["packets_per_second"] = [10, 11, 10, 9, 12]
    flows["bytes_per_second"] = [100, 110, 100, 90, 120]
    assert detect_statistical_anomalies(flows) == []


def test_empty_flows():
    flows = pd.DataFrame(columns=[
        "source_ip", "destination_ip",
        "packets_per_second", "bytes_per_second"
    ])
    assert detect_statistical_anomalies(flows) == []


def test_missing_columns():
    with pytest.raises(ValueError, match="Missing required columns"):
        detect_statistical_anomalies(pd.DataFrame({"source_ip": ["A"]}))


def test_invalid_threshold():
    with pytest.raises(ValueError):
        detect_statistical_anomalies(sample_flows(), z_score_threshold=0)
