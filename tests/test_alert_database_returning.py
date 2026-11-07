
import sqlite3

from ids import database


def test_sqlite_returning_and_duplicate_suppression():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT,
            detection_source TEXT,
            rule_id TEXT,
            severity TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            evidence TEXT,
            capture_name TEXT
        )
    """)

    connection.execute("""
        CREATE UNIQUE INDEX idx_alert_dedup
        ON alerts (
            analysis_id,
            detection_source,
            rule_id,
            IFNULL(source_ip, ''),
            IFNULL(destination_ip, ''),
            IFNULL(source_port, -1),
            IFNULL(destination_port, -1),
            IFNULL(protocol, ''),
            evidence
        )
    """)

    sql = """
        INSERT OR IGNORE INTO alerts (
            analysis_id, detection_source, rule_id, severity,
            source_ip, destination_ip, source_port, destination_port,
            protocol, evidence, capture_name
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id, analysis_id, rule_id, evidence
    """

    values = (
        "test-run", "packet", "PORT_SCAN_SUSPECTED", "medium",
        "192.168.1.50", "192.168.1.20", None, None, "TCP",
        "Test evidence", "test.pcap",
    )

    first = connection.execute(sql, values).fetchall()
    second = connection.execute(sql, values).fetchall()

    assert len(first) == 1
    assert first[0]["rule_id"] == "PORT_SCAN_SUSPECTED"
    assert len(second) == 0

    connection.close()


def test_actual_save_alerts_returning_with_temporary_database(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "test_ids.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)

    # Create the actual project schema and indexes in the temporary DB.
    database.initialize_database()

    alert = {
        "rule_id": "TEST_BROADCAST_RULE",
        "severity": "medium",
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "source_port": 12345,
        "destination_port": 443,
        "protocol": "TCP",
        "evidence": "Temporary integration test only",
    }

    first = database.save_alerts_returning(
        alerts=[alert],
        capture_name="temporary-test.pcap",
        analysis_id="temporary-analysis",
        detection_source="packet",
    )

    second = database.save_alerts_returning(
        alerts=[alert],
        capture_name="temporary-test.pcap",
        analysis_id="temporary-analysis",
        detection_source="packet",
    )

    assert len(first) == 1
    assert first[0]["rule_id"] == "TEST_BROADCAST_RULE"
    assert first[0]["id"] is not None
    assert second == []
