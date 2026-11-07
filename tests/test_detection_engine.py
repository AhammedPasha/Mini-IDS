
import pandas as pd

from ids.detection_engine import detect_suspicious_traffic


def test_detects_multiple_destination_ports():
    df = pd.DataFrame([
        {
            "timestamp": 1000 + i,
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "protocol": "TCP",
            "destination_port": 1000 + i,
        }
        for i in range(10)
    ])

    alerts = detect_suspicious_traffic(df, port_scan_threshold=10)

    scan_alerts = [
        alert for alert in alerts
        if alert["rule_id"] == "PORT_SCAN_SUSPECTED"
    ]

    assert len(scan_alerts) == 1
    assert scan_alerts[0]["severity"] == "medium"


def test_empty_dataframe_returns_no_alerts():
    df = pd.DataFrame(columns=[
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "destination_port",
    ])

    assert detect_suspicious_traffic(df) == []


import pytest



def test_detects_port_scan_within_time_window():
    df = pd.DataFrame({
        "source_ip": ["192.168.1.50"] * 4,
        "destination_ip": ["192.168.1.20"] * 4,
        "protocol": ["TCP"] * 4,
        "destination_port": [1001, 1002, 1003, 1004],
        "timestamp": [100, 105, 110, 115],
    })

    alerts = detect_suspicious_traffic(
        df,
        port_scan_threshold=4,
        time_window_seconds=60,
    )

    assert any(
        alert["rule_id"] == "PORT_SCAN_SUSPECTED"
        for alert in alerts
    )


def test_does_not_combine_different_protocols_for_port_scan():
    df = pd.DataFrame({
        "source_ip": ["10.0.0.1"] * 4,
        "destination_ip": ["10.0.0.2"] * 4,
        "protocol": ["TCP", "TCP", "UDP", "UDP"],
        "destination_port": [1001, 1002, 1003, 1004],
        "timestamp": [100, 101, 102, 103],
    })

    alerts = detect_suspicious_traffic(
        df,
        port_scan_threshold=3,
        time_window_seconds=60,
    )

    assert not any(
        alert["rule_id"] == "PORT_SCAN_SUSPECTED"
        for alert in alerts
    )


def test_does_not_combine_ports_from_separate_time_buckets():
    df = pd.DataFrame({
        "source_ip": ["10.0.0.1"] * 4,
        "destination_ip": ["10.0.0.2"] * 4,
        "protocol": ["TCP"] * 4,
        "destination_port": [1001, 1002, 1003, 1004],
        "timestamp": [10, 11, 70, 71],
    })

    alerts = detect_suspicious_traffic(
        df,
        port_scan_threshold=3,
        time_window_seconds=60,
    )

    assert not any(
        alert["rule_id"] == "PORT_SCAN_SUSPECTED"
        for alert in alerts
    )


def test_rejects_invalid_time_window():
    df = pd.DataFrame({
        "source_ip": ["10.0.0.1"],
        "destination_ip": ["10.0.0.2"],
        "protocol": ["TCP"],
        "destination_port": [443],
    })

    with pytest.raises(ValueError):
        detect_suspicious_traffic(df, time_window_seconds=0)
