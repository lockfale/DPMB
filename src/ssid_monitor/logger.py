"""Detection event logger for the WiFi probe request monitor."""

import logging
import sqlite3

logger = logging.getLogger(__name__)


def log_detection(
    db: sqlite3.Connection,
    ssid: str,
    device_id: str,
    rssi: int,
    device_mac: str | None = None,
    channel: int | None = None,
    alert_sent: bool = False,
) -> int:
    """Insert a detection event and return the new event ID."""
    cursor = db.execute(
        """
        INSERT INTO detection_events (ssid, device_id, rssi, device_mac, channel, alert_sent)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (ssid, device_id, rssi, device_mac, channel, 1 if alert_sent else 0),
    )
    db.commit()
    logger.debug("Detection logged: %s from %s RSSI=%d alert=%s", ssid, device_mac, rssi, alert_sent)
    return cursor.lastrowid


def _parse_since(since: str) -> str:
    """Parse a --since value into an ISO 8601 datetime string.

    Accepts:
        - Relative: "24h", "7d", "30m"
        - ISO 8601: "2026-02-27T00:00:00Z" or "2026-02-27"
    """
    from datetime import datetime, timedelta, timezone

    since = since.strip()

    # Relative format
    if since.endswith("h"):
        hours = int(since[:-1])
        dt = datetime.now(timezone.utc) - timedelta(hours=hours)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    elif since.endswith("d"):
        days = int(since[:-1])
        dt = datetime.now(timezone.utc) - timedelta(days=days)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    elif since.endswith("m"):
        minutes = int(since[:-1])
        dt = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        # Assume ISO 8601 — if just a date, append time
        if "T" not in since:
            since = since + "T00:00:00Z"
        return since


def query_events(
    db: sqlite3.Connection,
    ssid: str | None = None,
    since: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Query detection events with optional filters.

    Args:
        db: Database connection.
        ssid: Filter by SSID name (exact match).
        since: Only events after this time (relative or ISO 8601).
        limit: Max events to return (default 50).

    Returns:
        List of event dicts, newest first.
    """
    conditions = []
    params: list = []

    if ssid:
        conditions.append("ssid = ?")
        params.append(ssid)

    if since:
        since_dt = _parse_since(since)
        conditions.append("detected_at >= ?")
        params.append(since_dt)

    where = " AND ".join(conditions) if conditions else "1=1"
    params.append(limit)

    rows = db.execute(
        f"SELECT * FROM detection_events WHERE {where} ORDER BY detected_at DESC LIMIT ?",
        params,
    ).fetchall()

    return [dict(row) for row in rows]


def export_events(
    db: sqlite3.Connection,
    fmt: str = "csv",
    output: str | None = None,
) -> str:
    """Export all detection events as CSV or JSON.

    Args:
        db: Database connection.
        fmt: Output format — "csv" or "json".
        output: File path to write to. None = return as string.

    Returns:
        Exported data as string (if output is None).
    """
    rows = db.execute(
        "SELECT * FROM detection_events ORDER BY detected_at"
    ).fetchall()

    events = [dict(row) for row in rows]

    if fmt == "json":
        import json
        data = json.dumps(events, indent=2)
    else:
        import csv
        import io
        buf = io.StringIO()
        if events:
            writer = csv.DictWriter(buf, fieldnames=events[0].keys())
            writer.writeheader()
            writer.writerows(events)
        data = buf.getvalue()

    if output:
        with open(output, "w") as f:
            f.write(data)
        logger.info("Exported %d events to %s (%s)", len(events), output, fmt)

    return data
