from ids.threat_prioritizer import prioritize_alerts


def test_alerts_are_sorted_by_priority():
    alerts = [
        {"rule_id": "LOW", "severity": "low", "confidence_score": 50},
        {"rule_id": "HIGH", "severity": "high", "confidence_score": 90},
        {"rule_id": "MEDIUM", "severity": "medium", "confidence_score": 70},
    ]

    result = prioritize_alerts(alerts)

    assert result[0]["rule_id"] == "HIGH"
    assert result[-1]["rule_id"] == "LOW"


def test_priority_score_calculation():
    result = prioritize_alerts([
        {"severity": "high", "confidence_score": 80}
    ])

    assert result[0]["priority_score"] == 77
    assert result[0]["priority"] == "high"


def test_unknown_severity_defaults_to_low():
    result = prioritize_alerts([
        {"severity": "unknown", "confidence_score": 50}
    ])

    assert result[0]["priority_score"] == 35
    assert result[0]["priority"] == "low"


def test_confidence_is_clamped():
    result = prioritize_alerts([
        {"severity": "critical", "confidence_score": 150}
    ])

    assert result[0]["priority_score"] == 100


def test_empty_alert_list():
    assert prioritize_alerts([]) == []


def test_original_fields_are_preserved():
    alert = {
        "rule_id": "TEST",
        "severity": "medium",
        "confidence_score": 70,
        "source_ip": "192.168.1.10",
    }

    result = prioritize_alerts([alert])

    assert result[0]["source_ip"] == "192.168.1.10"
    assert result[0]["rule_id"] == "TEST"