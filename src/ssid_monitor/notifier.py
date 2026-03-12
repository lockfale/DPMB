"""Push notifications via ntfy.sh — zero-signup, instant mobile alerts."""

import logging
import urllib.request
import urllib.error
import json

logger = logging.getLogger(__name__)

# Default ntfy topic — user should customize this
NTFY_TOPIC = "dpmb-alerts"
NTFY_SERVER = "https://ntfy.sh"


def send_notification(title: str, message: str, priority: str = "high",
                      tags: list[str] | None = None,
                      topic: str | None = None,
                      server: str | None = None) -> bool:
    """Send a push notification via ntfy.sh.

    Args:
        title: Notification title
        message: Notification body
        priority: urgent, high, default, low, min
        tags: Emoji tags (e.g. ["rotating_light", "warning"])
        topic: ntfy topic (defaults to NTFY_TOPIC)
        server: ntfy server URL (defaults to NTFY_SERVER)

    Returns:
        True if sent successfully, False otherwise.
    """
    url = f"{server or NTFY_SERVER}/{topic or NTFY_TOPIC}"

    headers = {
        "Title": title,
        "Priority": priority,
    }
    if tags:
        headers["Tags"] = ",".join(tags)

    try:
        req = urllib.request.Request(
            url,
            data=message.encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                logger.info("ntfy notification sent: %s", title)
                return True
            else:
                logger.warning("ntfy returned status %d", resp.status)
                return False
    except urllib.error.URLError as e:
        logger.warning("ntfy send failed: %s", e)
        return False
    except Exception as e:
        logger.warning("ntfy unexpected error: %s", e)
        return False


def send_pushover(title: str, message: str, priority: str = "high",
                  user_key: str = "", api_token: str = "") -> bool:
    """Send a push notification via Pushover.

    Args:
        title: Notification title
        message: Notification body
        priority: urgent, high, default, low, min
        user_key: Pushover user key
        api_token: Pushover API token

    Returns:
        True if sent successfully, False otherwise.
    """
    priority_map = {"urgent": 2, "high": 1, "default": 0, "low": -1, "min": -2}
    prio_val = priority_map.get(priority, 0)

    payload = json.dumps({
        "token": api_token,
        "user": user_key,
        "title": title,
        "message": message,
        "priority": prio_val,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            "https://api.pushover.net/1/messages.json",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                logger.info("Pushover notification sent: %s", title)
                return True
            else:
                logger.warning("Pushover returned status %d", resp.status)
                return False
    except urllib.error.URLError as e:
        logger.warning("Pushover send failed: %s", e)
        return False
    except Exception as e:
        logger.warning("Pushover unexpected error: %s", e)
        return False


def dispatch_notification(title: str, message: str, priority: str = "high",
                          tags: list[str] | None = None,
                          db_path: str | None = None) -> bool:
    """Route notification to all enabled channels based on DB settings.

    Falls back to ntfy with default topic if no settings exist.
    """
    if not db_path:
        return send_notification(title, message, priority=priority, tags=tags)

    try:
        import sqlite3
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        conn.close()
        settings = {r[0]: r[1] for r in rows}
    except Exception:
        logger.debug("Could not read settings, falling back to default ntfy")
        return send_notification(title, message, priority=priority, tags=tags)

    sent_any = False

    # ntfy channel
    ntfy_enabled = settings.get("ntfy_enabled", "1")  # default on for backward compat
    if ntfy_enabled == "1":
        topic = settings.get("ntfy_topic") or NTFY_TOPIC
        server = settings.get("ntfy_server") or NTFY_SERVER
        if send_notification(title, message, priority=priority, tags=tags,
                             topic=topic, server=server):
            sent_any = True

    # Pushover channel
    pushover_enabled = settings.get("pushover_enabled", "0")
    if pushover_enabled == "1":
        user_key = settings.get("pushover_user_key", "")
        api_token = settings.get("pushover_api_token", "")
        if user_key and api_token:
            if send_pushover(title, message, priority=priority,
                             user_key=user_key, api_token=api_token):
                sent_any = True

    return sent_any


def notify_watchlist_match(ssid: str, device_mac: str, rssi: int,
                           channel: int, topic: str | None = None,
                           db_path: str | None = None) -> bool:
    """Send alert for a watchlist SSID match."""
    title_str = f"WATCHLIST MATCH: {ssid}"
    message_str = (
        f"Device {device_mac} probing for watched SSID\n"
        f"RSSI: {rssi} dBm | Channel: {channel}\n"
        f"Take appropriate action."
    )
    if db_path:
        return dispatch_notification(title_str, message_str, priority="urgent",
                                     tags=["rotating_light", "warning"], db_path=db_path)
    return send_notification(title_str, message_str, priority="urgent",
                             tags=["rotating_light", "warning"], topic=topic)


def notify_le_signature(ssid: str, device_mac: str, detail: str,
                         rssi: int, topic: str | None = None,
                         db_path: str | None = None) -> bool:
    """Send alert for LE/government signature detection."""
    title_str = f"LE SIGNATURE: {detail}"
    message_str = (
        f"SSID: {ssid}\n"
        f"Device: {device_mac} | RSSI: {rssi} dBm\n"
        f"LE equipment detected nearby."
    )
    if db_path:
        return dispatch_notification(title_str, message_str, priority="high",
                                     tags=["police_car", "eyes"], db_path=db_path)
    return send_notification(title_str, message_str, priority="high",
                             tags=["police_car", "eyes"], topic=topic)


def notify_deauth_burst(source_mac: str, target_mac: str, count: int,
                          channel: int, topic: str | None = None,
                          db_path: str | None = None) -> bool:
    """Send alert for deauth burst (possible attack)."""
    title_str = f"DEAUTH BURST: {count}x on CH{channel}"
    message_str = (
        f"Source: {source_mac}\n"
        f"Target: {target_mac}\n"
        f"{count} deauth frames detected — possible attack or handshake capture."
    )
    if db_path:
        return dispatch_notification(title_str, message_str, priority="high",
                                     tags=["skull", "zap"], db_path=db_path)
    return send_notification(title_str, message_str, priority="high",
                             tags=["skull", "zap"], topic=topic)


def notify_new_device(mac: str, ssids: list[str],
                       topic: str | None = None,
                       db_path: str | None = None) -> bool:
    """Send alert for a new device appearing."""
    ssid_list = ", ".join(ssids[:5]) if ssids else "none"
    title_str = f"NEW DEVICE: {mac}"
    message_str = f"Probing for: {ssid_list}"
    if db_path:
        return dispatch_notification(title_str, message_str, priority="default",
                                     tags=["new", "mag"], db_path=db_path)
    return send_notification(title_str, message_str, priority="default",
                             tags=["new", "mag"], topic=topic)


def notify_wids_alert(alert_type: str, severity: str, detail: str,
                       topic: str | None = None,
                       db_path: str | None = None) -> bool:
    """Send push notification for a WIDS alert."""
    severity_tags = {
        "critical": (["rotating_light", "skull"], "urgent"),
        "high": (["warning", "zap"], "high"),
        "medium": (["eyes", "mag"], "default"),
    }
    tags, priority = severity_tags.get(severity, (["bell"], "default"))

    title_map = {
        "evil_twin": "EVIL TWIN DETECTED",
        "karma_attack": "KARMA/MANA ATTACK",
        "encryption_downgrade": "ENCRYPTION DOWNGRADE",
        "channel_switch": "AP CHANNEL SWITCH",
        "auth_flood": "AUTH FLOOD ATTACK",
        "known_device_untrusted_ap": "KNOWN DEVICE → UNTRUSTED AP",
        "deauth_attack": "ACTIVE DEAUTH ATTACK",
    }
    title = title_map.get(alert_type, f"WIDS: {alert_type}")

    title_str = f"WIDS: {title}"
    if db_path:
        return dispatch_notification(title_str, detail, priority=priority,
                                     tags=tags, db_path=db_path)
    return send_notification(title_str, detail, priority=priority,
                             tags=tags, topic=topic)


def notify_health_degradation(alert_type: str, detail: str,
                                topic: str | None = None,
                                db_path: str | None = None) -> bool:
    """Send push notification for network health degradation."""
    title_map = {
        "signal_degradation": "SIGNAL DEGRADATION",
        "channel_congestion": "CHANNEL CONGESTION",
        "beacon_loss": "BEACON LOSS DETECTED",
    }
    title = title_map.get(alert_type, f"HEALTH: {alert_type}")

    priority = "high" if alert_type == "signal_degradation" else "default"
    tags = ["chart_with_downwards_trend", "warning"] if alert_type == "signal_degradation" else ["bar_chart", "eyes"]

    title_str = f"NETWORK HEALTH: {title}"
    if db_path:
        return dispatch_notification(title_str, detail, priority=priority,
                                     tags=tags, db_path=db_path)
    return send_notification(title_str, detail, priority=priority,
                             tags=tags, topic=topic)
