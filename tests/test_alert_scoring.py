
from ids.alert_scoring import calculate_alert_confidence


def test_high_confidence_alert():
    alert = {
        "rule_id": "PORT_SCAN_SUSPECTED",
        "severity": "medium",
        "evidence": "10 distinct destination ports; threshold is 10",
    }

    result = calculate_alert_confidence(alert)

    assert result["confidence_score"] == 95
    assert result["confidence_level"] == "high"


def test_medium_confidence_alert():
    alert = {
        "rule_id": "REPEATED_CONNECTION_ATTEMPTS",
        "severity": "medium",
        "evidence": "20 separate flows",
    }

    result = calculate_alert_confidence(alert)

    assert result["confidence_score"] == 75
    assert result["confidence_level"] == "medium"


def test_unknown_rule_uses_default_score():
    result = calculate_alert_confidence({
        "rule_id": "UNKNOWN_RULE",
        "evidence": "Unrecognised activity",
    })

    assert result["confidence_score"] == 50
    assert result["confidence_level"] == "low"


def test_confidence_never_exceeds_100():
    result = calculate_alert_confidence({
        "rule_id": "PORT_SCAN_SUSPECTED",
        "evidence": "distinct destination ports within a threshold",
    })

    assert result["confidence_score"] <= 100


def test_original_alert_fields_are_preserved():
    alert = {
        "rule_id": "HIGH_VOLUME_FLOW",
        "severity": "medium",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "evidence": "1000 packets; threshold is 1000",
    }

    result = calculate_alert_confidence(alert)

    assert result["source_ip"] == alert["source_ip"]
    assert result["destination_ip"] == alert["destination_ip"]
    assert result["severity"] == alert["severity"]