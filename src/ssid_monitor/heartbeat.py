"""Daily heartbeat module — builds device status payload and delivers to webhook."""

import logging
import sqlite3
from datetime import datetime, timedelta, timezone

import requests

from ssid_monitor.config import Config

logger = logging.getLogger(__name__)


def _read_uptime() -> int:
    """Read system uptime from /proc/uptime and return whole seconds.

    Returns:
        Integer uptime in seconds, or 0 if the file cannot be read.
    """
    try:
        with open("/proc/uptime") as f:
            first_field = f.read().split()[0]
            return int(float(first_field))
    except (FileNotFoundError, OSError, ValueError, IndexError):
        logger.debug("/proc/uptime not available, defaulting uptime to 0")
        return 0


def send_heartbeat(config: Config, db: sqlite3.Connection) -> tuple[int, str]:
    """Build and POST a heartbeat payload to the configured webhook.

    The payload reports device status including uptime, active watchlist
    size, and detection event count over the last 24 hours.

    Args:
        config: Application configuration with device_id, webhook_url, and db_path.
        db: Open SQLite connection with watchlist and detection_events tables.

    Returns:
        (status_code, response_text) from the webhook, or (0, error_message)
        if the request fails entirely.
    """
    uptime_seconds = _read_uptime()

    watchlist_count = db.execute(
        "SELECT COUNT(*) FROM watchlist WHERE active = 1"
    ).fetchone()[0]

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    events_last_24h = db.execute(
        "SELECT COUNT(*) FROM detection_events WHERE detected_at >= ?",
        (cutoff,),
    ).fetchone()[0]

    payload = {
        "type": "heartbeat",
        "device_id": config.device_id,
        "status": "active",
        "uptime_seconds": uptime_seconds,
        "watchlist_count": watchlist_count,
        "events_last_24h": events_last_24h,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    logger.info("Sending heartbeat for device %s", config.device_id)
    logger.debug("Heartbeat payload: %s", payload)

    try:
        resp = requests.post(config.webhook_url, json=payload, timeout=10)
        logger.info(
            "Heartbeat delivered: status=%d, body=%s",
            resp.status_code,
            resp.text[:200],
        )
        return (resp.status_code, resp.text)
    except requests.RequestException as exc:
        error_msg = str(exc)
        logger.error("Heartbeat delivery failed: %s", error_msg)
        return (0, error_msg)
