
import sqlite3
import uuid
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "mini_ids.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS analysis_runs (
                analysis_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                capture_name TEXT NOT NULL,
                capture_hash TEXT NOT NULL,
                threshold INTEGER NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                evidence TEXT NOT NULL,
                capture_name TEXT
            )
        """)

        # SECURITY INCIDENT MANAGEMENT TABLE
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                priority TEXT NOT NULL DEFAULT 'MEDIUM',
                source_ip TEXT,
                destination_ip TEXT,
                rule_id TEXT,
                evidence TEXT,
                notes TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Add analyst assignment support to incidents.
        incident_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(incidents)"
            )
        }

        if "assigned_to" not in incident_columns:
            connection.execute(
                "ALTER TABLE incidents ADD COLUMN assigned_to TEXT"
            )

        # Migrate older databases without deleting existing records.
        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(alerts)"
            )
        }

        migrations = {
            "analysis_id": "TEXT",
            "detection_source": "TEXT NOT NULL DEFAULT 'packet'",
            "source_port": "INTEGER",
            "destination_port": "INTEGER",
            "protocol": "TEXT",
            "confidence_score": "REAL",
            "confidence_level": "TEXT",
            "priority_score": "REAL",
            "priority": "TEXT",
        }

        for column_name, column_type in migrations.items():
            if column_name not in columns:
                connection.execute(
                    f"ALTER TABLE alerts ADD COLUMN "
                    f"{column_name} {column_type}"
                )

        # Replace the older deduplication index with a richer identity.
        connection.execute("DROP INDEX IF EXISTS idx_alert_dedup")

        connection.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_dedup
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


def create_analysis_run(
    capture_name: str,
    capture_hash: str,
    threshold: int,
) -> str:
    analysis_id = str(uuid.uuid4())

    with get_connection() as connection:
        connection.execute("""
            INSERT INTO analysis_runs (
                analysis_id,
                capture_name,
                capture_hash,
                threshold
            )
            VALUES (?, ?, ?, ?)
        """, (analysis_id, capture_name, capture_hash, threshold))

    return analysis_id


def save_alerts(
    alerts: list[dict],
    capture_name: str = "",
    analysis_id: str | None = None,
    detection_source: str = "packet",
) -> int:
    if detection_source not in {"packet", "flow"}:
        raise ValueError(
            "detection_source must be 'packet' or 'flow'"
        )

    if not alerts:
        return 0

    rows = []

    for alert in alerts:
        rows.append((
            analysis_id,
            detection_source,
            alert["rule_id"],
            alert["severity"],
            alert.get("source_ip"),
            alert.get("destination_ip"),
            alert.get("source_port"),
            alert.get("destination_port"),
            alert.get("protocol"),
            alert.get("confidence_score"),
            alert.get("confidence_level"),
            alert.get("priority_score"),
            alert.get("priority"),
            alert["evidence"],
            capture_name,
        ))

    with get_connection() as connection:
        cursor = connection.executemany("""
           INSERT OR IGNORE INTO alerts (
    analysis_id,
    detection_source,
    rule_id,
    severity,
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol,
    confidence_score,
    confidence_level,
    priority_score,
    priority,
    evidence,
    capture_name
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)

    return cursor.rowcount


def get_alert_history(limit: int = 100) -> list[dict]:
    if limit < 1:
        raise ValueError("limit must be at least 1")

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT
                id,
                created_at,
                analysis_id,
                detection_source,
                rule_id,
                severity,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol,
                confidence_score,
                confidence_level,
                priority_score,
                priority,
                evidence,
                capture_name
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


def get_analysis_history(limit: int = 50) -> list[dict]:
    if limit < 1:
        raise ValueError("limit must be at least 1")

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT
                analysis_id,
                created_at,
                capture_name,
                capture_hash,
                threshold
            FROM analysis_runs
            ORDER BY created_at DESC, rowid DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


def save_alerts_returning(
    alerts: list[dict],
    capture_name: str = "",
    analysis_id: str | None = None,
    detection_source: str = "packet",
) -> list[dict]:
    """Save alerts and return only records inserted by this call."""
    if detection_source not in {"packet", "flow"}:
        raise ValueError(
            "detection_source must be 'packet' or 'flow'"
        )

    if not alerts:
        return []

    rows = [
        (
            analysis_id,
            detection_source,
            alert["rule_id"],
            alert["severity"],
            alert.get("source_ip"),
            alert.get("destination_ip"),
            alert.get("source_port"),
            alert.get("destination_port"),
            alert.get("protocol"),
            alert.get("confidence_score"),
            alert.get("confidence_level"),
            alert.get("priority_score"),
            alert.get("priority"),
            alert["evidence"],
            capture_name,
        )
        for alert in alerts
    ]

    with get_connection() as connection:
        inserted_rows = connection.execute(
            """
            INSERT OR IGNORE INTO alerts (
               analysis_id,
detection_source,
rule_id,
severity,
source_ip,
destination_ip,
source_port,
destination_port,
protocol,
confidence_score,
confidence_level,
priority_score,
priority,
evidence,
capture_name
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING
                id,
                created_at,
                analysis_id,
                detection_source,
                rule_id,
                severity,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol,
                confidence_score,
confidence_level,
priority_score,
priority,
                evidence,
                capture_name
            """,
            rows[0],
        ).fetchall()

        for row in rows[1:]:
          inserted_rows.extend(
             connection.execute(
            """
            INSERT OR IGNORE INTO alerts (
                analysis_id,
                detection_source,
                rule_id,
                severity,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol,
                confidence_score,
                confidence_level,
                priority_score,
                priority,
                evidence,
                capture_name
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING
                id,
                created_at,
                analysis_id,
                detection_source,
                rule_id,
                severity,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol,
                confidence_score,
                confidence_level,
                priority_score,
                priority,
                evidence,
                capture_name
            """,
            row,
        ).fetchall()
    )
    return [dict(row) for row in inserted_rows]

# =====================================
# SECURITY INCIDENT MANAGEMENT
# =====================================


def create_incident(alert, title, priority="MEDIUM", notes=""):

    alert_id = alert.get("id")
    source_ip = alert.get("source_ip", "Unknown")
    destination_ip = alert.get("destination_ip", "Unknown")
    rule_id = alert.get(
        "rule_id",
        alert.get("alert_type", "Unknown")
    )
    evidence = str(
        alert.get("evidence", "No evidence available")
    )

    with get_connection() as connection:

        # Check whether this exact alert already has an incident.
        if alert_id is not None:
            existing = connection.execute("""
                SELECT incident_id
                FROM incidents
                WHERE alert_id = ?
                ORDER BY incident_id DESC
                LIMIT 1
            """, (alert_id,)).fetchone()

            if existing:
                return existing["incident_id"]

        # Reuse an existing active case for the same threat.
        existing = connection.execute("""
            SELECT incident_id
            FROM incidents
            WHERE source_ip = ?
              AND destination_ip = ?
              AND rule_id = ?
              AND status IN ('OPEN', 'INVESTIGATING')
            ORDER BY incident_id DESC
            LIMIT 1
        """, (
            source_ip,
            destination_ip,
            rule_id
        )).fetchone()

        if existing:
            return existing["incident_id"]

        # Create a new incident only if no active case exists.
        cursor = connection.execute("""
            INSERT INTO incidents (
                alert_id,
                title,
                status,
                priority,
                source_ip,
                destination_ip,
                rule_id,
                evidence,
                notes
            )
            VALUES (?, ?, 'OPEN', ?, ?, ?, ?, ?, ?)
        """, (
            alert_id,
            title,
            priority,
            source_ip,
            destination_ip,
            rule_id,
            evidence,
            notes
        ))

        return cursor.lastrowid




def get_incidents():
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT *
            FROM incidents
            ORDER BY created_at DESC
        """).fetchall()

        return [dict(row) for row in rows]


def update_incident(incident_id, status, priority, notes):
    with get_connection() as connection:
        connection.execute("""
            UPDATE incidents
            SET status = ?,
                priority = ?,
                notes = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE incident_id = ?
        """, (status, priority, notes, incident_id))


def add_incident_note(incident_id, analyst, note):
    if not note or not note.strip():
        raise ValueError("Note cannot be empty")

    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_notes (
                note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                analyst TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(incident_id)
            )
        """)

        cursor = connection.execute("""
            INSERT INTO incident_notes (incident_id, analyst, note)
            VALUES (?, ?, ?)
        """, (incident_id, analyst, note.strip()))

        connection.execute("""
            UPDATE incidents
            SET updated_at = CURRENT_TIMESTAMP
            WHERE incident_id = ?
        """, (incident_id,))

        return cursor.lastrowid


def get_incident_notes(incident_id):
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_notes (
                note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                analyst TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(incident_id)
            )
        """)

        rows = connection.execute("""
            SELECT *
            FROM incident_notes
            WHERE incident_id = ?
            ORDER BY created_at DESC, note_id DESC
        """, (incident_id,)).fetchall()

        return [dict(row) for row in rows]


def assign_incident(incident_id, assigned_to):
    if not assigned_to or not assigned_to.strip():
        raise ValueError("Analyst name cannot be empty")

    with get_connection() as connection:
        cursor = connection.execute("""
            UPDATE incidents
            SET assigned_to = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE incident_id = ?
        """, (assigned_to.strip(), incident_id))

        return cursor.rowcount > 0

# ============================================================
# HISTORY MANAGEMENT — DELETE OPERATIONS
# ============================================================

def delete_alert(alert_id: int) -> bool:
    """Delete one saved alert record."""
    with get_connection() as connection:
        cursor = connection.execute(
            "DELETE FROM alerts WHERE id = ?",
            (alert_id,)
        )
        return cursor.rowcount > 0


def clear_alert_history() -> int:
    """Delete all saved alert records."""
    with get_connection() as connection:
        cursor = connection.execute(
            "DELETE FROM alerts"
        )
        return cursor.rowcount


def delete_analysis_run(analysis_id: str) -> bool:
    """Delete one analysis history record."""
    with get_connection() as connection:
        cursor = connection.execute(
            "DELETE FROM analysis_runs WHERE analysis_id = ?",
            (analysis_id,)
        )
        return cursor.rowcount > 0


def clear_analysis_history() -> int:
    """Delete all analysis history records."""
    with get_connection() as connection:
        cursor = connection.execute(
            "DELETE FROM analysis_runs"
        )
        return cursor.rowcount

def delete_incident(incident_id: int) -> bool:
    with get_connection() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_notes (
                note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                analyst TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(incident_id)
            )
        """)

        connection.execute(
            "DELETE FROM incident_notes WHERE incident_id = ?",
            (incident_id,)
        )

        cursor = connection.execute(
            "DELETE FROM incidents WHERE incident_id = ?",
            (incident_id,)
        )

        return cursor.rowcount > 0


def clear_incidents() -> int:
    with get_connection() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_notes (
                note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                analyst TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(incident_id)
            )
        """)

        connection.execute("DELETE FROM incident_notes")
        cursor = connection.execute("DELETE FROM incidents")

        return cursor.rowcount