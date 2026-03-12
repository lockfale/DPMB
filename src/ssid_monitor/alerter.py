"""Webhook alerter module — deduplication, delivery with retry, and failed-alert queue."""

import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import requests

logger = logging.getLogger(__name__)


def check_cooldown(db: sqlite3.Connection, ssid: str) -> bool:
    """Check whether an SSID is currently in alert cooldown.

    Args:
        db: SQLite connection with the alerts table.
        ssid: The SSID to check.

    Returns:
        True if the SSID is in cooldown (alert should be skipped),
        False if clear to send a new alert.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    row = db.execute(
        "SELECT 1 FROM alerts WHERE ssid = ? AND cooldown_until > ? LIMIT 1",
        (ssid, now),
    ).fetchone()
    return row is not None


def send_alert(webhook_url: str, payload: dict) -> tuple[int, str]:
    """POST a JSON payload to the webhook URL with retries.

    Attempts up to 3 times with exponential backoff (1s, 2s, 4s).

    Args:
        webhook_url: Target URL for the POST request.
        payload: Dictionary to send as JSON body.

    Returns:
        (status_code, response_text) on success, or
        (0, error_message) if all retries are exhausted.
    """
    max_attempts = 3
    last_error = ""

    for attempt in range(max_attempts):
        delay = 2 ** attempt  # 1, 2, 4
        try:
            logger.info(
                "Webhook attempt %d/%d to %s", attempt + 1, max_attempts, webhook_url
            )
            resp = requests.post(webhook_url, json=payload, timeout=10)
            logger.info(
                "Webhook response: status=%d, body=%s",
                resp.status_code,
                resp.text[:200],
            )
            return (resp.status_code, resp.text)
        except requests.RequestException as exc:
            last_error = str(exc)
            logger.warning(
                "Webhook attempt %d/%d failed: %s", attempt + 1, max_attempts, last_error
            )
            if attempt < max_attempts - 1:
                time.sleep(delay)

    logger.error("All %d webhook attempts failed. Last error: %s", max_attempts, last_error)
    return (0, last_error)


def record_alert(
    db: sqlite3.Connection,
    ssid: str,
    device_id: str,
    webhook_status: int,
    webhook_response: str,
    cooldown_min: int,
) -> int:
    """Record an alert in the database and set the cooldown window.

    Args:
        db: SQLite connection.
        ssid: The detected SSID.
        device_id: Identifier of the monitoring device.
        webhook_status: HTTP status code from the webhook (0 if failed).
        webhook_response: Response body from the webhook.
        cooldown_min: Minutes to suppress duplicate alerts for this SSID.

    Returns:
        The auto-generated alert ID.
    """
    now = datetime.now(timezone.utc)
    cooldown_until = now + timedelta(minutes=cooldown_min)
    truncated_response = webhook_response[:500]

    cursor = db.execute(
        """INSERT INTO alerts (ssid, device_id, webhook_status, webhook_response, cooldown_until)
           VALUES (?, ?, ?, ?, ?)""",
        (
            ssid,
            device_id,
            webhook_status,
            truncated_response,
            cooldown_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
    )
    db.commit()
    return cursor.lastrowid


def build_detection_payload(
    ssid: str,
    device_mac: str,
    rssi: int,
    channel: int,
    device_id: str,
    alert_id: int,
) -> dict:
    """Build the webhook JSON payload for a probe request detection.

    Args:
        ssid: SSID the client device was probing for.
        device_mac: MAC address of the client device that sent the probe.
        rssi: Received signal strength indicator (dBm).
        channel: WiFi channel the probe was observed on.
        device_id: Identifier of the monitoring device.
        alert_id: Database ID of the recorded alert.

    Returns:
        Dictionary matching the detection webhook contract.
    """
    return {
        "type": "detection",
        "ssid": ssid,
        "device_mac": device_mac,
        "rssi": rssi,
        "channel": channel,
        "device_id": device_id,
        "detected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "alert_id": alert_id,
    }


def queue_failed_alert(db: sqlite3.Connection, payload: dict) -> None:
    """Persist a failed alert payload for later retry.

    Args:
        db: SQLite connection with the failed_alerts table.
        payload: The webhook payload that failed to deliver.
    """
    db.execute(
        "INSERT INTO failed_alerts (payload) VALUES (?)",
        (json.dumps(payload),),
    )
    db.commit()


def flush_failed_queue(
    db: sqlite3.Connection, webhook_url: str, max_per_cycle: int = 10
) -> int:
    """Retry sending the oldest queued failed alerts.

    Args:
        db: SQLite connection.
        webhook_url: Target URL for the POST requests.
        max_per_cycle: Maximum number of queued alerts to process.

    Returns:
        Count of alerts successfully flushed (sent and deleted).
    """
    rows = db.execute(
        "SELECT id, payload FROM failed_alerts ORDER BY created_at ASC LIMIT ?",
        (max_per_cycle,),
    ).fetchall()

    flushed = 0
    for row in rows:
        payload = json.loads(row["payload"])
        status_code, _ = send_alert(webhook_url, payload)
        if status_code != 0:
            db.execute("DELETE FROM failed_alerts WHERE id = ?", (row["id"],))
            db.commit()
            flushed += 1
            logger.info("Flushed queued alert id=%d (status=%d)", row["id"], status_code)
        else:
            logger.warning("Queued alert id=%d still failing, leaving in queue", row["id"])

    return flushed
