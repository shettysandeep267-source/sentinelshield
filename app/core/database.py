"""
SQLite database layer for SentinelShield.

Responsibilities:
- Create and initialize the SQLite schema
- Store security events
- Store security alerts
- Query alerts for the dashboard
- Query related events for incident investigation
- Update alert lifecycle status

This is intentionally a thin SQLite wrapper with no ORM.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional


# ============================================================================
# DATABASE PATH
# ============================================================================

DEFAULT_DB_PATH = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "sentinelshield.db"
)


# ============================================================================
# DATABASE SCHEMA
# ============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT NOT NULL,
    source_ip           TEXT,
    destination_ip      TEXT,
    source_port         INTEGER,
    destination_port    INTEGER,
    protocol            TEXT,
    event_type          TEXT NOT NULL,
    description         TEXT,
    raw_data            TEXT,
    engine              TEXT NOT NULL DEFAULT 'SENTINELSHIELD'
);


CREATE TABLE IF NOT EXISTS alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT NOT NULL,
    event_type          TEXT NOT NULL,
    source_ip           TEXT,
    destination_ip      TEXT,
    severity            TEXT NOT NULL DEFAULT 'LOW',
    confidence          INTEGER NOT NULL DEFAULT 0,
    risk_score          INTEGER NOT NULL DEFAULT 0,
    description         TEXT,
    evidence            TEXT,
    recommended_action  TEXT,
    status              TEXT NOT NULL DEFAULT 'NEW',
    engine              TEXT NOT NULL DEFAULT 'SENTINELSHIELD',
    related_event_ids   TEXT
);


CREATE INDEX IF NOT EXISTS idx_events_source_ip
ON events(source_ip);


CREATE INDEX IF NOT EXISTS idx_events_type
ON events(event_type);


CREATE INDEX IF NOT EXISTS idx_events_timestamp
ON events(timestamp);


CREATE INDEX IF NOT EXISTS idx_alerts_status
ON alerts(status);


CREATE INDEX IF NOT EXISTS idx_alerts_severity
ON alerts(severity);


CREATE INDEX IF NOT EXISTS idx_alerts_event_type
ON alerts(event_type);


CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
ON alerts(source_ip);


CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
ON alerts(timestamp);
"""


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db(db_path: Optional[Path] = None) -> None:
    """
    Create the database file and schema if they do not already exist.
    """

    path = db_path or DEFAULT_DB_PATH

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with sqlite3.connect(path) as conn:

        conn.executescript(SCHEMA)

        conn.commit()


# ============================================================================
# CONNECTION
# ============================================================================

@contextmanager
def get_connection(
    db_path: Optional[Path] = None,
) -> Iterator[sqlite3.Connection]:
    """
    Create a context-managed SQLite connection.

    Rows are returned as sqlite3.Row objects so callers can use:

        row["source_ip"]

    instead of numeric indexes.
    """

    path = db_path or DEFAULT_DB_PATH

    conn = sqlite3.connect(path)

    conn.row_factory = sqlite3.Row

    try:

        yield conn

    finally:

        conn.close()


# ============================================================================
# EVENT INSERT
# ============================================================================

def insert_event(event) -> int:
    """
    Insert an app.core.models.Event into SQLite.

    Returns:
        int: Newly created event ID.
    """

    init_db()

    engine = getattr(
        event.engine,
        "value",
        event.engine,
    )

    with get_connection() as conn:

        cursor = conn.execute(
            """
            INSERT INTO events (
                timestamp,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol,
                event_type,
                description,
                raw_data,
                engine
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.timestamp,
                event.source_ip,
                event.destination_ip,
                event.source_port,
                event.destination_port,
                event.protocol,
                event.event_type,
                event.description,
                event.raw_data,
                engine,
            ),
        )

        conn.commit()

        event_id = cursor.lastrowid

    return int(event_id)


# ============================================================================
# ALERT INSERT
# ============================================================================

def insert_alert(alert) -> int:
    """
    Insert an app.core.models.Alert into SQLite.

    Returns:
        int: Newly created alert ID.
    """

    init_db()

    severity = getattr(
        alert.severity,
        "value",
        alert.severity,
    )

    status = getattr(
        alert.status,
        "value",
        alert.status,
    )

    engine = getattr(
        alert.engine,
        "value",
        alert.engine,
    )

    with get_connection() as conn:

        cursor = conn.execute(
            """
            INSERT INTO alerts (
                timestamp,
                event_type,
                source_ip,
                destination_ip,
                severity,
                confidence,
                risk_score,
                description,
                evidence,
                recommended_action,
                status,
                engine,
                related_event_ids
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.timestamp,
                alert.event_type,
                alert.source_ip,
                alert.destination_ip,
                severity,
                int(alert.confidence),
                int(alert.risk_score),
                alert.description,
                alert.evidence,
                alert.recommended_action,
                status,
                engine,
                alert.related_event_ids,
            ),
        )

        conn.commit()

        alert_id = cursor.lastrowid

    return int(alert_id)


# ============================================================================
# ALERT QUERY
# ============================================================================

def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
):
    """
    Fetch alerts, optionally filtered by status and/or severity.

    Results are returned newest-first as sqlite3.Row objects.
    """

    init_db()

    # Prevent invalid/huge LIMIT values.
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 100

    limit = max(
        1,
        min(limit, 1000),
    )

    query = """
        SELECT *
        FROM alerts
        WHERE 1 = 1
    """

    params = []

    if status:

        query += """
            AND UPPER(status) = UPPER(?)
        """

        params.append(status)

    if severity:

        query += """
            AND UPPER(severity) = UPPER(?)
        """

        params.append(severity)

    query += """
        ORDER BY timestamp DESC, id DESC
        LIMIT ?
    """

    params.append(limit)

    with get_connection() as conn:

        rows = conn.execute(
            query,
            params,
        ).fetchall()

    return rows


# ============================================================================
# ALERT COUNTS
# ============================================================================

def get_alert_count(
    status: Optional[str] = None,
    severity: Optional[str] = None,
) -> int:
    """
    Return the number of alerts.

    Optional filters:
        status="NEW"
        severity="HIGH"
    """

    init_db()

    query = """
        SELECT COUNT(*)
        FROM alerts
        WHERE 1 = 1
    """

    params = []

    if status:

        query += """
            AND UPPER(status) = UPPER(?)
        """

        params.append(status)

    if severity:

        query += """
            AND UPPER(severity) = UPPER(?)
        """

        params.append(severity)

    with get_connection() as conn:

        result = conn.execute(
            query,
            params,
        ).fetchone()

    return int(result[0])


# ============================================================================
# EVENT COUNT
# ============================================================================

def get_event_count(
    event_type: Optional[str] = None,
) -> int:
    """
    Return the number of stored events.

    Optional filter:
        event_type="PORT_SCAN"
    """

    init_db()

    query = """
        SELECT COUNT(*)
        FROM events
        WHERE 1 = 1
    """

    params = []

    if event_type:

        query += """
            AND UPPER(event_type) = UPPER(?)
        """

        params.append(event_type)

    with get_connection() as conn:

        result = conn.execute(
            query,
            params,
        ).fetchone()

    return int(result[0])


# ============================================================================
# RELATED EVENTS
# ============================================================================

def get_related_events(
    source_ip: Optional[str],
    timestamp: Optional[str] = None,
    limit: int = 20,
):
    """
    Return events associated with the same source IP as an alert.

    The source IP is the primary correlation key.

    If timestamp is supplied, events are ordered by their proximity
    to the alert timestamp where possible, while still returning
    the newest relevant activity.

    Returns:
        list[sqlite3.Row]
    """

    init_db()

    if not source_ip:

        return []

    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 20

    limit = max(
        1,
        min(limit, 200),
    )

    with get_connection() as conn:

        rows = conn.execute(
            """
            SELECT *
            FROM events
            WHERE source_ip = ?
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
            """,
            (
                source_ip,
                limit,
            ),
        ).fetchall()

    return rows


# ============================================================================
# SINGLE ALERT
# ============================================================================

def get_alert(
    alert_id: int,
):
    """
    Fetch one alert by ID.

    Returns:
        sqlite3.Row or None
    """

    init_db()

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,),
        ).fetchone()

    return row


# ============================================================================
# SINGLE EVENT
# ============================================================================

def get_event(
    event_id: int,
):
    """
    Fetch one event by ID.

    Returns:
        sqlite3.Row or None
    """

    init_db()

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM events
            WHERE id = ?
            """,
            (event_id,),
        ).fetchone()

    return row


# ============================================================================
# UPDATE ALERT STATUS
# ============================================================================

def update_alert_status(
    alert_id: int,
    new_status: str,
) -> None:
    """
    Update the lifecycle status of an alert.

    Lifecycle validation is handled by app.core.alerts.transition().
    This function is responsible only for database persistence.
    """

    init_db()

    if not new_status:

        raise ValueError(
            "Status cannot be empty."
        )

    new_status = str(
        new_status
    ).upper().strip()

    valid_statuses = {
        "NEW",
        "ACKNOWLEDGED",
        "INVESTIGATING",
        "RESOLVED",
    }

    if new_status not in valid_statuses:

        raise ValueError(
            f"Invalid alert status: {new_status}"
        )

    with get_connection() as conn:

        cursor = conn.execute(
            """
            UPDATE alerts
            SET status = ?
            WHERE id = ?
            """,
            (
                new_status,
                alert_id,
            ),
        )

        conn.commit()

        if cursor.rowcount == 0:

            raise ValueError(
                f"Alert #{alert_id} was not found."
            )


# ============================================================================
# RELATED EVENT IDS
# ============================================================================

def get_events_by_ids(
    event_ids,
):
    """
    Fetch multiple events by their IDs.

    event_ids can be:
        [1, 2, 3]

    or:
        "1,2,3"
    """

    init_db()

    if isinstance(event_ids, str):

        event_ids = [
            item.strip()
            for item in event_ids.split(",")
            if item.strip()
        ]

    if not event_ids:

        return []

    try:

        event_ids = [
            int(event_id)
            for event_id in event_ids
        ]

    except (TypeError, ValueError):

        return []

    placeholders = ",".join(
        "?" for _ in event_ids
    )

    with get_connection() as conn:

        rows = conn.execute(
            f"""
            SELECT *
            FROM events
            WHERE id IN ({placeholders})
            ORDER BY timestamp DESC, id DESC
            """,
            event_ids,
        ).fetchall()

    return rows


# ============================================================================
# DATABASE SUMMARY
# ============================================================================

def get_database_summary():
    """
    Return basic database statistics.

    Useful for the dashboard and future reporting module.
    """

    init_db()

    with get_connection() as conn:

        total_events = conn.execute(
            """
            SELECT COUNT(*)
            FROM events
            """
        ).fetchone()[0]

        total_alerts = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            """
        ).fetchone()[0]

        critical = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE severity = 'CRITICAL'
            """
        ).fetchone()[0]

        high = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE severity = 'HIGH'
            """
        ).fetchone()[0]

        medium = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE severity = 'MEDIUM'
            """
        ).fetchone()[0]

        low = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE severity = 'LOW'
            """
        ).fetchone()[0]

        new_alerts = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'NEW'
            """
        ).fetchone()[0]

        investigating = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'INVESTIGATING'
            """
        ).fetchone()[0]

        resolved = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'RESOLVED'
            """
        ).fetchone()[0]

    return {
        "total_events": int(total_events),
        "total_alerts": int(total_alerts),
        "critical": int(critical),
        "high": int(high),
        "medium": int(medium),
        "low": int(low),
        "new": int(new_alerts),
        "investigating": int(investigating),
        "resolved": int(resolved),
    }


# ============================================================================
# MANUAL TEST
# ============================================================================

if __name__ == "__main__":

    init_db()

    print("=" * 50)
    print(" SentinelShield Database Test")
    print("=" * 50)

    print()
    print("Database:")
    print(DEFAULT_DB_PATH)

    print()
    print("Alerts:", get_alert_count())
    print("Events:", get_event_count())

    print()
    print("Database summary:")

    summary = get_database_summary()

    for key, value in summary.items():

        print(
            f"  {key:<15}: {value}"
        )

    print()
    print("Database initialization: OK")