
import ids.database as database


def test_save_and_read_alerts(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database, "DB_PATH", tmp_path / "test_ids.db"
    )
    database.initialize_database()

    alerts = [{
        "rule_id": "PORT_SCAN_SUSPECTED",
        "severity": "medium",
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.20",
        "evidence": "12 distinct destination ports observed",
    }]

    analysis_id = database.create_analysis_run(
        "sample_traffic.pcap", "test-hash", 10
    )

    assert database.save_alerts(
        alerts, "sample_traffic.pcap", analysis_id
    ) == 1

    # Saving the same alert in the same run must not duplicate it.
    assert database.save_alerts(
        alerts, "sample_traffic.pcap", analysis_id
    ) == 0

    history = database.get_alert_history()
    assert len(history) == 1
    assert history[0]["analysis_id"] == analysis_id

    # A separate analysis run may legitimately produce the same alert.
    second_run = database.create_analysis_run(
        "sample_traffic.pcap", "test-hash", 10
    )
    assert database.save_alerts(
        alerts, "sample_traffic.pcap", second_run
    ) == 1

    assert len(database.get_analysis_history()) == 2
    assert len(database.get_alert_history()) == 2
def test_save_alerts_with_confidence_and_priority(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database, "DB_PATH", tmp_path / "test_scoring.db"
    )
    database.initialize_database()

    alerts = [
        {
            "rule_id": "PORT_SCAN_SUSPECTED",
            "severity": "medium",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.20",
            "evidence": "12 distinct destination ports observed",
            "confidence_score": 85.0,
            "confidence_level": "high",
            "priority_score": 75.0,
            "priority": "high",
        },
        {
            "rule_id": "SENSITIVE_SERVICE_TRAFFIC",
            "severity": "low",
            "source_ip": "192.168.1.60",
            "destination_ip": "192.168.1.20",
            "evidence": "SMB traffic detected",
            "confidence_score": 60.0,
            "confidence_level": "medium",
            "priority_score": 40.0,
            "priority": "medium",
        },
    ]

    analysis_id = database.create_analysis_run(
        "sample_traffic.pcap", "scoring-test", 15
    )

    saved_count = database.save_alerts(
        alerts, "sample_traffic.pcap", analysis_id
    )

    assert saved_count == 2

    history = database.get_alert_history()

    assert len(history) == 2

    port_scan = next(
        alert for alert in history
        if alert["rule_id"] == "PORT_SCAN_SUSPECTED"
    )

    assert port_scan["confidence_score"] == 85.0
    assert port_scan["confidence_level"] == "high"
    assert port_scan["priority_score"] == 75.0
    assert port_scan["priority"] == "high"