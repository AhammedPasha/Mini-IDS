
import pandas as pd
import pytest

from ids.flow_analyzer import analyze_flows


def sample_traffic():
    return pd.DataFrame({
        "timestamp": [100.0, 101.0, 103.0, 105.0],
        "source_ip": [
            "10.0.0.1",
            "10.0.0.1",
            "10.0.0.1",
            "10.0.0.2",
        ],
        "destination_ip": [
            "10.0.0.2",
            "10.0.0.2",
            "10.0.0.2",
            "10.0.0.1",
        ],
        "protocol": ["TCP", "TCP", "TCP", "TCP"],
        "source_port": [50000, 50000, 50000, 443],
        "destination_port": [443, 443, 443, 50000],
        "packet_length": [100, 200, 150, 120],
    })


def test_groups_packets_into_directional_flows():
    flows = analyze_flows(sample_traffic())

    assert len(flows) == 2

    forward = flows[
        (flows["source_ip"] == "10.0.0.1")
        & (flows["destination_ip"] == "10.0.0.2")
    ].iloc[0]

    assert forward["packet_count"] == 3
    assert forward["total_bytes"] == 450
    assert forward["duration_seconds"] == 3.0


def test_reverse_direction_is_a_separate_flow():
    flows = analyze_flows(sample_traffic())

    reverse = flows[
        (flows["source_ip"] == "10.0.0.2")
        & (flows["destination_ip"] == "10.0.0.1")
    ].iloc[0]

    assert reverse["packet_count"] == 1
    assert reverse["total_bytes"] == 120


def test_empty_input_returns_empty_flow_table():
    traffic = sample_traffic().iloc[0:0]

    flows = analyze_flows(traffic)

    assert flows.empty
    assert "packet_count" in flows.columns


def test_missing_required_column_raises_error():
    traffic = sample_traffic().drop(columns=["protocol"])

    with pytest.raises(ValueError, match="protocol"):
        analyze_flows(traffic)


def test_zero_duration_flow_has_finite_rates():
    traffic = sample_traffic().iloc[[0]].copy()

    flows = analyze_flows(traffic)

    assert flows.iloc[0]["duration_seconds"] == 0
    assert flows.iloc[0]["packets_per_second"] == 0
    assert flows.iloc[0]["bytes_per_second"] == 0
