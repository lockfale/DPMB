"""802.11 probe request scanner — monitor mode setup, device tracking, and security detection."""

import logging
import subprocess
from collections import Counter, namedtuple
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

ProbeFrame = namedtuple("ProbeFrame", ["ssid", "device_mac", "rssi", "channel"])
DeauthFrame = namedtuple("DeauthFrame", ["device_mac", "target_mac", "rssi", "channel", "reason"])
BeaconFrame = namedtuple("BeaconFrame", [
    "bssid", "ssid", "channel", "rssi", "encryption", "is_probe_resp",
])
AuthFrame = namedtuple("AuthFrame", [
    "device_mac", "bssid", "rssi", "channel", "frame_subtype",
])
ScanResult = namedtuple("ScanResult", ["probes", "deauths", "beacons", "auths", "eapol_packets"])

# How long before a device is considered "departed" (seconds)
PRESENCE_TIMEOUT_SEC = 300


# ---------------------------------------------------------------------------
# Wireless interface discovery
# ---------------------------------------------------------------------------

def _find_iw() -> str:
    """Locate the ``iw`` binary, checking common sbin paths systemd may omit."""
    import shutil
    path = shutil.which("iw")
    if path:
        return path
    for candidate in ("/usr/sbin/iw", "/sbin/iw"):
        if subprocess.run(["test", "-x", candidate], capture_output=True).returncode == 0:
            return candidate
    return "iw"  # fallback — let subprocess raise if missing


def discover_wireless_interfaces() -> list[dict]:
    """Enumerate wireless interfaces via ``iw dev``.

    Returns a list of dicts: ``{"name": "wlan0", "addr": "aa:bb:...", "type": "managed"}``.
    """
    try:
        result = subprocess.run(
            [_find_iw(), "dev"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return []
    except Exception:
        return []

    interfaces = []
    current: dict | None = None
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Interface "):
            if current:
                interfaces.append(current)
            current = {"name": stripped.split()[1], "addr": "", "type": ""}
        elif current:
            if stripped.startswith("addr "):
                current["addr"] = stripped.split()[1]
            elif stripped.startswith("type "):
                current["type"] = stripped.split()[1]
    if current:
        interfaces.append(current)

    return interfaces


def auto_select_interface(configured: str = "") -> str:
    """Return the best wireless interface to use.

    Priority:
      1. Explicitly configured interface (if non-empty and exists)
      2. An interface already in monitor mode
      3. The first wireless interface found

    Returns empty string if nothing is found.
    """
    if configured:
        # Verify it actually exists
        found = discover_wireless_interfaces()
        if any(iface["name"] == configured for iface in found):
            return configured
        # Interface configured but not present — log and fall through
        logger.warning("Configured interface %s not found — attempting auto-discovery", configured)

    found = discover_wireless_interfaces()
    if not found:
        return ""

    # Prefer one already in monitor mode
    for iface in found:
        if iface["type"] == "monitor":
            logger.info("Auto-selected %s (already in monitor mode)", iface["name"])
            return iface["name"]

    # Otherwise pick the first one
    logger.info("Auto-selected wireless interface: %s", found[0]["name"])
    return found[0]["name"]


# ---------------------------------------------------------------------------
# Monitor / Managed mode helpers
# ---------------------------------------------------------------------------

def _is_monitor_mode(interface: str) -> bool:
    """Check if the interface is already in monitor mode without touching it."""
    try:
        result = subprocess.run(
            [_find_iw(), "dev", interface, "info"],
            capture_output=True, text=True, timeout=5,
        )
        return "type monitor" in result.stdout
    except Exception:
        return False


def setup_monitor_mode(interface: str) -> None:
    """Put a wireless interface into monitor mode.

    Skips setup entirely if the interface is already in monitor mode to
    avoid disruptive down/up cycles that can break USB WiFi adapters
    (especially under VM passthrough).

    Uses ``iw`` + ``ip`` (preferred — less disruptive to USB adapters).
    Falls back to PyRIC if subprocess fails.

    Raises:
        RuntimeError: If neither method succeeds.
    """
    # --- skip if already in monitor mode ------------------------------------
    if _is_monitor_mode(interface):
        # Ensure the interface is UP
        try:
            subprocess.run(
                ["ip", "link", "set", interface, "up"],
                capture_output=True, text=True, timeout=5,
            )
        except Exception:
            pass
        logger.info("Monitor mode already active on %s — skipping setup", interface)
        return

    # --- attempt 1: subprocess (ip / iw) — preferred for USB adapters ------
    try:
        subprocess.run(
            ["ip", "link", "set", interface, "down"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            [_find_iw(), "dev", interface, "set", "type", "monitor"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["ip", "link", "set", interface, "up"],
            check=True, capture_output=True, text=True,
        )
        logger.info("Monitor mode set on %s via subprocess (ip/iw)", interface)
        return
    except Exception as exc:
        logger.debug("Subprocess failed for %s: %s — falling back to PyRIC", interface, exc)

    # --- attempt 2: PyRIC (fallback) ----------------------------------------
    try:
        import pyric.pyw as pyw  # type: ignore[import-untyped]

        iface = pyw.getcard(interface)
        pyw.down(iface)
        pyw.modeset(iface, "monitor")
        pyw.up(iface)
        logger.info("Monitor mode set on %s via PyRIC", interface)
        return
    except ImportError:
        logger.debug("PyRIC not installed")
    except Exception as exc:
        raise RuntimeError(
            f"Failed to set monitor mode on {interface}: {exc}"
        ) from exc


def restore_managed_mode(interface: str) -> None:
    """Best-effort restore of a wireless interface to managed mode.

    Uses the same PyRIC-then-subprocess strategy as
    :func:`setup_monitor_mode`.  Failures are logged as warnings but
    never raised — the caller should not crash on cleanup errors.
    """
    # --- attempt 1: PyRIC ---------------------------------------------------
    try:
        import pyric.pyw as pyw  # type: ignore[import-untyped]

        iface = pyw.getcard(interface)
        pyw.down(iface)
        pyw.modeset(iface, "managed")
        pyw.up(iface)
        logger.info("Managed mode restored on %s via PyRIC", interface)
        return
    except ImportError:
        logger.debug("PyRIC not installed — falling back to subprocess")
    except Exception as exc:
        logger.debug("PyRIC failed restoring %s: %s — falling back to subprocess", interface, exc)

    # --- attempt 2: subprocess (ip / iw) ------------------------------------
    try:
        subprocess.run(
            ["ip", "link", "set", interface, "down"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            [_find_iw(), "dev", interface, "set", "type", "managed"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["ip", "link", "set", interface, "up"],
            check=True, capture_output=True, text=True,
        )
        logger.info("Managed mode restored on %s via subprocess (ip/iw)", interface)
    except Exception as exc:
        logger.warning("Could not restore managed mode on %s: %s", interface, exc)


# ---------------------------------------------------------------------------
# Probe request scanning
# ---------------------------------------------------------------------------

CHANNELS_24GHZ = list(range(1, 12))  # channels 1-11


def _hop_channel(interface: str, channel: int) -> bool:
    """Switch monitor-mode interface to the given channel. Returns True on success."""
    try:
        subprocess.run(
            [_find_iw(), "dev", interface, "set", "channel", str(channel)],
            check=True, capture_output=True, text=True, timeout=5,
        )
        return True
    except Exception:
        logger.debug("Failed to hop to channel %d on %s", channel, interface)
        return False


def scan_cycle(interface: str, timeout: int = 10, priority_channels: set[int] | None = None) -> ScanResult:
    """Run a combined probe request + deauth capture cycle on *interface*.

    Hops through 2.4 GHz channels (1-11), capturing management frames.
    Priority channels (e.g. channels used by owned APs) get 3x dwell time.
    Returns both probe requests and deauthentication frames.
    """
    try:
        from scapy.all import sniff, Dot11, Dot11ProbeReq, Dot11Elt, Dot11Deauth, Dot11Beacon, Dot11ProbeResp, RadioTap  # noqa: F811

        # Allocate dwell time: priority channels get 3x weight
        prio = priority_channels or set()
        total_weight = sum(3 if ch in prio else 1 for ch in CHANNELS_24GHZ)
        per_channel_base = max(0.5, timeout / total_weight)
        probes: list[ProbeFrame] = []
        deauths: list[DeauthFrame] = []
        beacons: list[BeaconFrame] = []
        auths: list[AuthFrame] = []
        eapol_pkts: list[tuple] = []  # (packet, ap_mac, sta_mac)
        seen: set[tuple[str, str]] = set()  # (device_mac, ssid) dedupe
        seen_beacons: set[tuple[str, str]] = set()  # (bssid, ssid) dedupe per cycle

        for ch in CHANNELS_24GHZ:
            _hop_channel(interface, ch)
            dwell = per_channel_base * (3 if ch in prio else 1)

            packets = sniff(
                iface=interface,
                filter="type mgt or type data",
                timeout=dwell,
                store=True,
            )

            for packet in packets:
                if not packet.haslayer(Dot11):
                    continue

                dot11 = packet[Dot11]
                frame_subtype = dot11.subtype

                rssi = 0
                if packet.haslayer(RadioTap):
                    rssi = getattr(packet[RadioTap], "dBm_AntSignal", 0) or 0

                # --- Probe Request (subtype 4) ----------------------------
                if frame_subtype == 4 and packet.haslayer(Dot11ProbeReq):
                    ssid = ""
                    elt = packet.getlayer(Dot11Elt)
                    while elt:
                        if elt.ID == 0:
                            ssid = elt.info.decode("utf-8", errors="replace")
                            break
                        elt = elt.payload.getlayer(Dot11Elt)

                    if not ssid:
                        continue

                    device_mac = dot11.addr2 or "00:00:00:00:00:00"
                    key = (device_mac, ssid)
                    if key in seen:
                        continue
                    seen.add(key)
                    probes.append(ProbeFrame(ssid=ssid, device_mac=device_mac, rssi=rssi, channel=ch))

                # --- Beacon (subtype 8) / Probe Response (subtype 5) -----
                elif frame_subtype in (5, 8):
                    bssid = dot11.addr2 or dot11.addr3 or "00:00:00:00:00:00"
                    ssid = ""
                    encryption = "Open"
                    beacon_ch = ch

                    # Parse information elements
                    elt = packet.getlayer(Dot11Elt)
                    has_rsn = False
                    has_wpa = False
                    while elt:
                        if elt.ID == 0:  # SSID
                            ssid = elt.info.decode("utf-8", errors="replace")
                        elif elt.ID == 3:  # DS Parameter Set (channel)
                            try:
                                beacon_ch = elt.info[0]
                            except (IndexError, TypeError):
                                pass
                        elif elt.ID == 48:  # RSN (WPA2/WPA3)
                            has_rsn = True
                        elif elt.ID == 221:  # Vendor-specific
                            try:
                                if elt.info[:4] == b'\x00\x50\xf2\x01':  # WPA OUI
                                    has_wpa = True
                            except (IndexError, TypeError):
                                pass
                        elt = elt.payload.getlayer(Dot11Elt)

                    # Determine encryption from capability + IEs
                    cap = 0
                    if packet.haslayer(Dot11Beacon):
                        cap = packet[Dot11Beacon].cap or 0
                    elif packet.haslayer(Dot11ProbeResp):
                        cap = packet[Dot11ProbeResp].cap or 0

                    privacy = bool(cap & 0x0010)  # privacy bit
                    if has_rsn:
                        encryption = "WPA2/WPA3"
                    elif has_wpa:
                        encryption = "WPA"
                    elif privacy:
                        encryption = "WEP"
                    else:
                        encryption = "Open"

                    bkey = (bssid, ssid)
                    if bkey not in seen_beacons:
                        seen_beacons.add(bkey)
                        beacons.append(BeaconFrame(
                            bssid=bssid, ssid=ssid, channel=beacon_ch,
                            rssi=rssi, encryption=encryption,
                            is_probe_resp=(frame_subtype == 5),
                        ))

                # --- Deauthentication (subtype 12) ------------------------
                elif frame_subtype == 12:
                    device_mac = dot11.addr2 or "00:00:00:00:00:00"
                    target_mac = dot11.addr1 or "ff:ff:ff:ff:ff:ff"
                    reason = 0
                    if packet.haslayer(Dot11Deauth):
                        reason = packet[Dot11Deauth].reason or 0
                    deauths.append(DeauthFrame(
                        device_mac=device_mac, target_mac=target_mac,
                        rssi=rssi, channel=ch, reason=reason,
                    ))

                # --- Auth / Assoc / Reassoc (subtypes 0,1,2,3,11) --------
                elif frame_subtype in (0, 1, 2, 3, 11):
                    device_mac = dot11.addr2 or "00:00:00:00:00:00"
                    bssid = dot11.addr1 if frame_subtype in (0, 2, 11) else dot11.addr2
                    bssid = bssid or "00:00:00:00:00:00"
                    # For responses (1, 3), addr1=client, addr2=AP
                    if frame_subtype in (1, 3):
                        device_mac = dot11.addr1 or "00:00:00:00:00:00"
                        bssid = dot11.addr2 or "00:00:00:00:00:00"
                    auths.append(AuthFrame(
                        device_mac=device_mac, bssid=bssid,
                        rssi=rssi, channel=ch, frame_subtype=frame_subtype,
                    ))

                # --- EAPOL (WPA handshake, data frames) -----------------
                if dot11.type == 2:
                    try:
                        from scapy.layers.eap import EAPOL as EAPOLLayer
                        if packet.haslayer(EAPOLLayer):
                            to_ds = bool(dot11.FCfield & 0x1)
                            from_ds = bool(dot11.FCfield & 0x2)
                            eap_ap = eap_sta = None
                            if to_ds and not from_ds:
                                eap_ap = dot11.addr1
                                eap_sta = dot11.addr2
                            elif from_ds and not to_ds:
                                eap_ap = dot11.addr2
                                eap_sta = dot11.addr1
                            if eap_ap and eap_sta:
                                eapol_pkts.append((packet, eap_ap, eap_sta))
                    except ImportError:
                        pass

        logger.info(
            "Scan cycle: %d probes, %d beacons, %d auths, %d deauths, %d eapol across %d channels on %s",
            len(probes), len(beacons), len(auths), len(deauths), len(eapol_pkts), len(CHANNELS_24GHZ), interface,
        )
        return ScanResult(probes=probes, deauths=deauths, beacons=beacons, auths=auths, eapol_packets=eapol_pkts)

    except Exception:
        logger.exception("Error during scan cycle on %s", interface)
        return ScanResult(probes=[], deauths=[], beacons=[], auths=[], eapol_packets=[])


# ---------------------------------------------------------------------------
# Interface health check
# ---------------------------------------------------------------------------

def _check_interface_health(interface: str) -> bool:
    """Verify the wireless interface exists and is in monitor mode.

    Returns True if healthy, False if interface is missing or not in monitor mode.
    Only checks sysfs existence and iw mode — does NOT check carrier state
    because some USB adapters (e.g. RT2800usb under VM passthrough) report
    NO-CARRIER / DORMANT even when functioning normally.
    """
    import os

    # Check if interface exists via sysfs
    if not os.path.exists(f"/sys/class/net/{interface}"):
        return False

    # Check if in monitor mode via iw
    return _is_monitor_mode(interface)


def _wait_for_interface(interface: str, notify_fn=None) -> None:
    """Block until the wireless interface is available and re-enable monitor mode.

    Polls every 5 seconds. Sends systemd status notifications if notify_fn provided.
    """
    import time

    logger.warning("Interface %s lost — waiting for recovery...", interface)
    if notify_fn:
        notify_fn(f"STATUS=Interface {interface} lost, waiting for recovery...")

    while True:
        import os
        if os.path.exists(f"/sys/class/net/{interface}"):
            logger.info("Interface %s detected — re-enabling monitor mode", interface)
            try:
                setup_monitor_mode(interface)
                logger.info("Monitor mode restored on %s — resuming scan", interface)
                if notify_fn:
                    notify_fn(f"STATUS=Monitoring on {interface}")
                return
            except RuntimeError:
                logger.warning("Failed to set monitor mode on %s — retrying in 5s", interface)

        time.sleep(5)

        # Keep systemd watchdog alive during recovery
        if notify_fn:
            notify_fn("WATCHDOG=1")


# ---------------------------------------------------------------------------
# Device tracking & intelligence
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def update_devices(db, probes: list[ProbeFrame]) -> list[str]:
    """Upsert device + device_ssid tables. Returns list of NEW device MACs."""
    new_devices = []
    now = _now_iso()

    for p in probes:
        mac = p.device_mac

        # Detect locally-administered (randomized) MAC address
        is_randomized = 1 if int(mac.split(':')[0], 16) & 0x02 != 0 else 0

        # Upsert device record
        existing = db.execute("SELECT mac FROM devices WHERE mac = ?", (mac,)).fetchone()
        if existing is None:
            db.execute(
                "INSERT INTO devices (mac, first_seen, last_seen, probe_count, avg_rssi, min_rssi, max_rssi, is_randomized) "
                "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
                (mac, now, now, p.rssi, p.rssi, p.rssi, is_randomized),
            )
            new_devices.append(mac)
        else:
            db.execute(
                "UPDATE devices SET last_seen = ?, probe_count = probe_count + 1, "
                "avg_rssi = (avg_rssi * probe_count + ?) / (probe_count + 1), "
                "min_rssi = MIN(COALESCE(min_rssi, 0), ?), "
                "max_rssi = MAX(COALESCE(max_rssi, -100), ?), "
                "is_randomized = ? "
                "WHERE mac = ?",
                (now, p.rssi, p.rssi, p.rssi, is_randomized, mac),
            )

        # Upsert SSID fingerprint
        if p.ssid:
            existing_ssid = db.execute(
                "SELECT count FROM device_ssids WHERE device_mac = ? AND ssid = ?",
                (mac, p.ssid),
            ).fetchone()
            if existing_ssid is None:
                db.execute(
                    "INSERT INTO device_ssids (device_mac, ssid, first_seen, last_seen, count) "
                    "VALUES (?, ?, ?, ?, 1)",
                    (mac, p.ssid, now, now),
                )
            else:
                db.execute(
                    "UPDATE device_ssids SET last_seen = ?, count = count + 1 "
                    "WHERE device_mac = ? AND ssid = ?",
                    (now, mac, p.ssid),
                )

    db.commit()
    return new_devices


def check_presence(db, probes: list[ProbeFrame]) -> None:
    """Detect arrive/depart events based on probe visibility."""
    now = _now_iso()
    now_dt = datetime.now(timezone.utc)
    cutoff = (now_dt - timedelta(seconds=PRESENCE_TIMEOUT_SEC)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # MACs seen this cycle
    seen_macs = {p.device_mac for p in probes}
    mac_rssi = {}
    mac_ssid = {}
    for p in probes:
        mac_rssi[p.device_mac] = p.rssi
        mac_ssid[p.device_mac] = p.ssid

    # Check arrivals: seen now, but last presence event was 'depart' or no event
    for mac in seen_macs:
        last_event = db.execute(
            "SELECT event_type FROM presence_log WHERE device_mac = ? ORDER BY timestamp DESC LIMIT 1",
            (mac,),
        ).fetchone()
        if last_event is None or last_event["event_type"] == "depart":
            db.execute(
                "INSERT INTO presence_log (device_mac, event_type, timestamp, rssi, ssid) "
                "VALUES (?, 'arrive', ?, ?, ?)",
                (mac, now, mac_rssi.get(mac, 0), mac_ssid.get(mac, "")),
            )
            logger.info("ARRIVE: %s (RSSI %d)", mac, mac_rssi.get(mac, 0))

    # Check departures: devices with 'arrive' as last event, not seen recently
    active_devices = db.execute(
        "SELECT DISTINCT device_mac FROM presence_log p1 "
        "WHERE event_type = 'arrive' AND timestamp = ("
        "  SELECT MAX(timestamp) FROM presence_log p2 WHERE p2.device_mac = p1.device_mac"
        ")"
    ).fetchall()

    for row in active_devices:
        mac = row["device_mac"]
        if mac in seen_macs:
            continue  # still here
        # Check if last probe was before the timeout
        last_probe = db.execute(
            "SELECT seen_at FROM probe_log WHERE device_mac = ? ORDER BY seen_at DESC LIMIT 1",
            (mac,),
        ).fetchone()
        if last_probe and last_probe["seen_at"] < cutoff:
            db.execute(
                "INSERT INTO presence_log (device_mac, event_type, timestamp, rssi) "
                "VALUES (?, 'depart', ?, 0)",
                (mac, now),
            )
            logger.info("DEPART: %s (absent >%ds)", mac, PRESENCE_TIMEOUT_SEC)

    db.commit()


def log_security_event(db, event_type: str, device_mac: str = None,
                       ssid: str = None, detail: str = None, rssi: int = None) -> None:
    """Insert a security event."""
    db.execute(
        "INSERT INTO security_events (event_type, device_mac, ssid, detail, rssi) "
        "VALUES (?, ?, ?, ?, ?)",
        (event_type, device_mac, ssid, detail, rssi),
    )
    db.commit()


def process_deauths(db, deauths: list[DeauthFrame]) -> None:
    """Log deauthentication frames as security events."""
    for d in deauths:
        log_security_event(
            db,
            event_type="deauth",
            device_mac=d.device_mac,
            detail=f"target={d.target_mac} reason={d.reason} ch={d.channel}",
            rssi=d.rssi,
        )
    if deauths:
        logger.warning("Captured %d deauth frames", len(deauths))


# ---------------------------------------------------------------------------
# WIDS — Wireless Intrusion Detection System
# ---------------------------------------------------------------------------

def _wids_alert_exists(db, alert_type: str, bssid: str = None, device_mac: str = None, minutes: int = 5) -> bool:
    """Check if a similar WIDS alert was already raised recently."""
    row = db.execute(
        "SELECT id FROM wids_alerts WHERE alert_type = ? "
        "AND COALESCE(bssid, '') = COALESCE(?, '') "
        "AND COALESCE(device_mac, '') = COALESCE(?, '') "
        "AND seen_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)",
        (alert_type, bssid or '', device_mac or '', f'-{minutes} minutes'),
    ).fetchone()
    return row is not None


def update_access_points(db, beacons: list[BeaconFrame]) -> None:
    """Upsert AP inventory and ap_history for change tracking.

    For each beacon frame: upserts into access_points (updating last_seen,
    beacon_count, RSSI stats, channel, and encryption if changed) and inserts
    a row into ap_history for historical tracking.  New APs are logged.
    """
    now = _now_iso()

    for b in beacons:
        existing = db.execute(
            "SELECT bssid, beacon_count, avg_rssi, min_rssi, max_rssi FROM access_points WHERE bssid = ?",
            (b.bssid,),
        ).fetchone()

        if existing is None:
            # New AP
            db.execute(
                "INSERT INTO access_points "
                "(bssid, ssid, channel, encryption, first_seen, last_seen, beacon_count, avg_rssi, min_rssi, max_rssi) "
                "VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
                (b.bssid, b.ssid, b.channel, b.encryption, now, now, b.rssi, b.rssi, b.rssi),
            )
            logger.info("NEW AP: %s (%s) ch=%d enc=%s RSSI=%d", b.bssid, b.ssid, b.channel, b.encryption, b.rssi)
        else:
            count = existing["beacon_count"]
            avg = existing["avg_rssi"] or 0
            mn = existing["min_rssi"] or 0
            mx = existing["max_rssi"] or -100
            new_avg = (avg * count + b.rssi) / (count + 1)
            new_min = min(mn, b.rssi)
            new_max = max(mx, b.rssi)
            db.execute(
                "UPDATE access_points SET ssid = ?, channel = ?, encryption = ?, last_seen = ?, "
                "beacon_count = beacon_count + 1, avg_rssi = ?, min_rssi = ?, max_rssi = ? "
                "WHERE bssid = ?",
                (b.ssid, b.channel, b.encryption, now, new_avg, new_min, new_max, b.bssid),
            )

        # Always insert into ap_history for change tracking
        db.execute(
            "INSERT INTO ap_history (bssid, ssid, channel, encryption, rssi) VALUES (?, ?, ?, ?, ?)",
            (b.bssid, b.ssid, b.channel, b.encryption, b.rssi),
        )

    db.commit()


def detect_evil_twin(db, beacons: list[BeaconFrame]) -> list[dict]:
    """Alert when the same SSID as a trusted AP appears with a different BSSID.

    For each beacon, checks if its SSID matches any trusted AP (is_trusted=1)
    that has a different BSSID.  If found, inserts a wids_alert with
    alert_type='evil_twin' and severity='critical'.  Deduplicates within 5 min.

    Returns:
        List of alert dicts for notification.
    """
    alerts: list[dict] = []

    for b in beacons:
        if not b.ssid:
            continue

        # Skip if this BSSID is itself trusted (multi-AP / mesh networks)
        self_trusted = db.execute(
            "SELECT bssid FROM access_points WHERE bssid = ? AND is_trusted = 1",
            (b.bssid,),
        ).fetchone()
        if self_trusted:
            continue

        # Check if any trusted AP with this SSID exists under a different BSSID
        trusted = db.execute(
            "SELECT bssid FROM access_points WHERE ssid = ? AND is_trusted = 1 AND bssid != ?",
            (b.ssid, b.bssid),
        ).fetchone()

        if trusted is None:
            continue

        if _wids_alert_exists(db, 'evil_twin', bssid=b.bssid):
            continue

        detail = (
            f"SSID '{b.ssid}' seen on BSSID {b.bssid} (ch={b.channel}, enc={b.encryption}) "
            f"— trusted BSSID is {trusted['bssid']}"
        )
        db.execute(
            "INSERT INTO wids_alerts (alert_type, severity, bssid, ssid, detail) "
            "VALUES ('evil_twin', 'critical', ?, ?, ?)",
            (b.bssid, b.ssid, detail),
        )
        db.commit()

        alert = {"alert_type": "evil_twin", "severity": "critical", "detail": detail}
        alerts.append(alert)
        logger.warning("WIDS EVIL TWIN: %s", detail)

    return alerts


def detect_karma(db, beacons: list[BeaconFrame]) -> list[dict]:
    """Alert when a single BSSID responds to many different SSIDs (>5).

    Filters beacons to only probe responses (is_probe_resp=True), groups by
    BSSID, and counts unique SSIDs.  If any BSSID responds to more than 5
    different SSIDs, inserts a wids_alert with alert_type='karma_attack' and
    severity='critical'.  Deduplicates within 5 minutes.

    Returns:
        List of alert dicts for notification.
    """
    alerts: list[dict] = []

    # Only probe responses
    probe_resps = [b for b in beacons if b.is_probe_resp]
    if not probe_resps:
        return alerts

    # Group by BSSID → set of unique SSIDs
    bssid_ssids: dict[str, set[str]] = {}
    for b in probe_resps:
        bssid_ssids.setdefault(b.bssid, set()).add(b.ssid)

    for bssid, ssids in bssid_ssids.items():
        if len(ssids) <= 5:
            continue

        if _wids_alert_exists(db, 'karma_attack', bssid=bssid):
            continue

        detail = (
            f"BSSID {bssid} responded to {len(ssids)} different SSIDs "
            f"(probe-response): {', '.join(sorted(ssids)[:10])}"
        )
        db.execute(
            "INSERT INTO wids_alerts (alert_type, severity, bssid, detail) "
            "VALUES ('karma_attack', 'critical', ?, ?)",
            (bssid, detail),
        )
        db.commit()

        alert = {"alert_type": "karma_attack", "severity": "critical", "detail": detail}
        alerts.append(alert)
        logger.warning("WIDS KARMA ATTACK: %s", detail)

    return alerts


def detect_beacon_anomaly(db, beacons: list[BeaconFrame]) -> list[dict]:
    """Alert on encryption downgrade or channel shift for known APs.

    For each beacon, looks up the existing AP in access_points.  If encryption
    changed from WPA2/WPA3 to WPA/WEP/Open, raises an 'encryption_downgrade'
    alert (severity='high').  If the channel changed, raises a 'channel_switch'
    alert (severity='medium').  Deduplicates within 5 minutes.

    Returns:
        List of alert dicts for notification.
    """
    alerts: list[dict] = []

    strong_enc = {"WPA2/WPA3"}
    weak_enc = {"WPA", "WEP", "Open"}

    for b in beacons:
        existing = db.execute(
            "SELECT ssid, channel, encryption FROM access_points WHERE bssid = ?",
            (b.bssid,),
        ).fetchone()

        if existing is None:
            continue

        old_enc = existing["encryption"]
        old_channel = existing["channel"]

        # Encryption downgrade check
        if old_enc in strong_enc and b.encryption in weak_enc:
            if not _wids_alert_exists(db, 'encryption_downgrade', bssid=b.bssid):
                detail = (
                    f"AP {b.bssid} ({b.ssid}) encryption downgraded: "
                    f"{old_enc} → {b.encryption}"
                )
                db.execute(
                    "INSERT INTO wids_alerts (alert_type, severity, bssid, ssid, detail) "
                    "VALUES ('encryption_downgrade', 'high', ?, ?, ?)",
                    (b.bssid, b.ssid, detail),
                )
                db.commit()

                alert = {"alert_type": "encryption_downgrade", "severity": "high", "detail": detail}
                alerts.append(alert)
                logger.warning("WIDS ENCRYPTION DOWNGRADE: %s", detail)

        # Channel switch check
        if old_channel is not None and b.channel != old_channel:
            if not _wids_alert_exists(db, 'channel_switch', bssid=b.bssid):
                detail = (
                    f"AP {b.bssid} ({b.ssid}) changed channel: "
                    f"{old_channel} → {b.channel}"
                )
                db.execute(
                    "INSERT INTO wids_alerts (alert_type, severity, bssid, ssid, detail) "
                    "VALUES ('channel_switch', 'medium', ?, ?, ?)",
                    (b.bssid, b.ssid, detail),
                )
                db.commit()

                alert = {"alert_type": "channel_switch", "severity": "medium", "detail": detail}
                alerts.append(alert)
                logger.info("WIDS CHANNEL SWITCH: %s", detail)

    return alerts


def detect_auth_flood(db, auths: list[AuthFrame]) -> list[dict]:
    """Alert when >20 auth/assoc frames originate from the same source MAC.

    Counts auth frames per device_mac using Counter.  If any device exceeds 20,
    inserts a wids_alert with alert_type='auth_flood' and severity='high'.
    Deduplicates within 5 minutes.

    Returns:
        List of alert dicts for notification.
    """
    alerts: list[dict] = []

    if not auths:
        return alerts

    mac_counts = Counter(a.device_mac for a in auths)

    for mac, cnt in mac_counts.items():
        if cnt <= 20:
            continue

        if _wids_alert_exists(db, 'auth_flood', device_mac=mac):
            continue

        detail = f"Device {mac} sent {cnt} auth/assoc frames in one scan cycle"
        db.execute(
            "INSERT INTO wids_alerts (alert_type, severity, device_mac, detail) "
            "VALUES ('auth_flood', 'high', ?, ?)",
            (mac, detail),
        )
        db.commit()

        alert = {"alert_type": "auth_flood", "severity": "high", "detail": detail}
        alerts.append(alert)
        logger.warning("WIDS AUTH FLOOD: %s", detail)

    return alerts


def track_associations(db, auths: list[AuthFrame]) -> list[dict]:
    """Track client-to-AP associations and alert on known devices joining untrusted APs.

    For each auth frame, upserts the client_associations table.  If the device
    is marked as known (is_known=1 in devices) and is associating with an
    untrusted AP (is_trusted != 1 in access_points), raises an alert with
    alert_type='known_device_untrusted_ap' and severity='medium'.

    Returns:
        List of alert dicts for notification.
    """
    alerts: list[dict] = []
    now = _now_iso()

    for a in auths:
        # Upsert client_associations
        existing = db.execute(
            "SELECT count FROM client_associations WHERE device_mac = ? AND bssid = ?",
            (a.device_mac, a.bssid),
        ).fetchone()

        if existing is None:
            db.execute(
                "INSERT INTO client_associations (device_mac, bssid, first_seen, last_seen, count) "
                "VALUES (?, ?, ?, ?, 1)",
                (a.device_mac, a.bssid, now, now),
            )
        else:
            db.execute(
                "UPDATE client_associations SET last_seen = ?, count = count + 1 "
                "WHERE device_mac = ? AND bssid = ?",
                (now, a.device_mac, a.bssid),
            )

        # Check: known device associating with untrusted AP
        device = db.execute(
            "SELECT is_known FROM devices WHERE mac = ?", (a.device_mac,)
        ).fetchone()
        if device is None or not device["is_known"]:
            continue

        ap = db.execute(
            "SELECT is_trusted, ssid FROM access_points WHERE bssid = ?", (a.bssid,)
        ).fetchone()
        if ap is not None and not ap["is_trusted"]:
            if _wids_alert_exists(db, 'known_device_untrusted_ap', device_mac=a.device_mac):
                continue

            ap_ssid = ap["ssid"] if ap else a.bssid
            detail = (
                f"Known device {a.device_mac} associating with untrusted AP "
                f"{a.bssid} ({ap_ssid}) on ch={a.channel}"
            )
            db.execute(
                "INSERT INTO wids_alerts (alert_type, severity, bssid, device_mac, detail) "
                "VALUES ('known_device_untrusted_ap', 'medium', ?, ?, ?)",
                (a.bssid, a.device_mac, detail),
            )
            db.commit()

            alert = {"alert_type": "known_device_untrusted_ap", "severity": "medium", "detail": detail}
            alerts.append(alert)
            logger.warning("WIDS KNOWN DEVICE → UNTRUSTED AP: %s", detail)

    db.commit()
    return alerts


def detect_deauth_attack(db, deauths: list, auths: list) -> list[dict]:
    """Detect deauthentication attacks by looking for patterns that distinguish
    real attacks from normal WiFi management traffic.

    Real attacks (aireplay-ng, mdk3/mdk4, bettercap):
      - Source spoofs a known AP MAC, blasting deauths to many different clients
      - OR broadcast deauths (target ff:ff:ff:ff:ff:ff) from a known AP MAC
      - Reason codes are typically 7 (class 3 frame) or 1 (unspecified)
      - Goal: force clients to reconnect so attacker captures handshakes

    Normal traffic this must NOT flag:
      - Band steering: AP deauths a single client to push it to 5GHz (reason 5)
      - Client roaming: client sends deauth to old AP (reason 3)
      - Idle disconnect: AP deauths idle client (reason 4)
      - Single client reconnection loops (connectivity issues)

    Severity is based on pattern confidence:
      - critical: broadcast deauths spoofing a known AP (always an attack)
      - high: targeted deauths from a known AP to 5+ distinct clients in one cycle
      - medium: unknown source targeting many clients on one AP

    Returns:
        List of alert dicts for notification.
    """
    alerts: list[dict] = []

    if not deauths:
        return alerts

    # Reason codes that indicate normal AP client management, not attacks.
    # 3 = leaving, 4 = inactivity, 5 = AP full (band steering), 8 = leaving BSS
    BENIGN_REASONS = {3, 4, 5, 8}

    # Build AP inventory for spoofing detection
    known_ap_macs = set()
    try:
        known_ap_macs = {
            r["bssid"]
            for r in db.execute("SELECT bssid FROM access_points").fetchall()
        }
    except Exception:
        pass

    # --- Pattern 1: Broadcast deauths spoofing a known AP ---
    # This is always an attack. No legitimate AP sends broadcast deauths.
    broadcast_deauths = [
        d for d in deauths
        if d.target_mac == "ff:ff:ff:ff:ff:ff"
        and d.device_mac in known_ap_macs
    ]
    if broadcast_deauths:
        by_source = Counter(d.device_mac for d in broadcast_deauths)
        for spoofed_ap, count in by_source.items():
            if count < 3:
                continue
            if _wids_alert_exists(db, 'deauth_attack', bssid=spoofed_ap, minutes=60):
                continue
            detail = (
                f"Broadcast deauth x{count} spoofing known AP {spoofed_ap} — "
                f"active deauth attack (handshake capture or DoS)"
            )
            db.execute(
                "INSERT INTO wids_alerts (alert_type, severity, bssid, detail) "
                "VALUES ('deauth_attack', 'critical', ?, ?)",
                (spoofed_ap, detail),
            )
            db.commit()
            alerts.append({"alert_type": "deauth_attack", "severity": "critical", "detail": detail})
            logger.warning("WIDS DEAUTH ATTACK (broadcast): %s", detail)

    # --- Pattern 2: Known AP MAC targeting many distinct clients ---
    # Legitimate: AP deauths 1-2 clients (band steering, idle timeout).
    # Attack: attacker spoofs AP MAC and blasts deauths to many clients.
    # Filter out benign reason codes first.
    suspicious_from_ap = [
        d for d in deauths
        if d.device_mac in known_ap_macs
        and d.target_mac != "ff:ff:ff:ff:ff:ff"
        and d.reason not in BENIGN_REASONS
    ]
    by_ap_source = {}
    for d in suspicious_from_ap:
        by_ap_source.setdefault(d.device_mac, set()).add(d.target_mac)

    for spoofed_ap, targets in by_ap_source.items():
        if len(targets) < 5:
            continue
        if _wids_alert_exists(db, 'deauth_attack', bssid=spoofed_ap, minutes=60):
            continue
        detail = (
            f"Deauths from AP {spoofed_ap} to {len(targets)} distinct clients "
            f"(reason codes not band-steering) — likely spoofed deauth attack"
        )
        db.execute(
            "INSERT INTO wids_alerts (alert_type, severity, bssid, detail) "
            "VALUES ('deauth_attack', 'high', ?, ?)",
            (spoofed_ap, detail),
        )
        db.commit()
        alerts.append({"alert_type": "deauth_attack", "severity": "high", "detail": detail})
        logger.warning("WIDS DEAUTH ATTACK (targeted): %s", detail)

    # --- Pattern 3: Unknown source flooding deauths at a known AP ---
    # An attacker who doesn't bother spoofing — just blasts deauths at an AP.
    # Only flag if targeting many distinct clients (not a single client reconnect loop).
    unknown_sources = [
        d for d in deauths
        if d.device_mac not in known_ap_macs
        and d.reason not in BENIGN_REASONS
    ]
    # Group by target AP (the AP being attacked)
    by_target_ap = {}
    for d in unknown_sources:
        if d.target_mac in known_ap_macs:
            by_target_ap.setdefault(d.target_mac, {"sources": set(), "count": 0})
            by_target_ap[d.target_mac]["sources"].add(d.device_mac)
            by_target_ap[d.target_mac]["count"] += 1

    for target_ap, info in by_target_ap.items():
        # Need high volume from unknown source(s) — not just one client disconnecting
        if info["count"] < 20:
            continue
        if _wids_alert_exists(db, 'deauth_attack', bssid=target_ap, minutes=60):
            continue
        source_str = ", ".join(list(info["sources"])[:5])
        detail = (
            f"Deauth flood x{info['count']} targeting AP {target_ap} "
            f"from unknown source(s) {source_str} — possible deauth attack"
        )
        db.execute(
            "INSERT INTO wids_alerts (alert_type, severity, bssid, detail) "
            "VALUES ('deauth_attack', 'medium', ?, ?)",
            (target_ap, detail),
        )
        db.commit()
        alerts.append({"alert_type": "deauth_attack", "severity": "medium", "detail": detail})
        logger.warning("WIDS DEAUTH ATTACK (flood): %s", detail)

    return alerts


def record_health_snapshot(db, beacons: list[BeaconFrame], probes: list[ProbeFrame]) -> list[dict]:
    """Record per-owned-BSSID health metrics and detect degradation.

    Returns list of health alert dicts for notification.
    """
    alerts = []
    now = _now_iso()

    # Get owned SSIDs
    try:
        owned_rows = db.execute(
            "SELECT ssid FROM watchlist WHERE active = 1 AND watch_type = 'owned'"
        ).fetchall()
        owned_ssids = {r["ssid"] for r in owned_rows}
    except Exception:
        return alerts

    if not owned_ssids:
        return alerts

    # Find owned BSSIDs from this cycle's beacons
    owned_beacons = [b for b in beacons if b.ssid in owned_ssids]

    # Sibling RSSI proxy: mesh APs share the first 5 octets across virtual
    # interfaces but the named-SSID interface beacons infrequently.  When we
    # don't capture the exact BSSID, use a sibling's RSSI as proxy.
    if not owned_beacons:
        # Look up known owned BSSIDs from database
        try:
            known_owned = db.execute(
                "SELECT DISTINCT nh.bssid, nh.ssid, nh.channel "
                "FROM network_health nh WHERE nh.ssid IN (%s) "
                "GROUP BY nh.bssid" % ",".join("?" * len(owned_ssids)),
                list(owned_ssids),
            ).fetchall()
        except Exception:
            known_owned = []

        # Build sibling prefix -> beacon map from this cycle
        cycle_by_prefix: dict[str, BeaconFrame] = {}
        for b in beacons:
            if b.rssi and b.rssi != 0:
                prefix = b.bssid[:14]  # first 5 octets e.g. "e8:d3:eb:02:2e"
                # Keep the strongest signal sibling
                if prefix not in cycle_by_prefix or b.rssi > cycle_by_prefix[prefix].rssi:
                    cycle_by_prefix[prefix] = b

        for row in known_owned:
            prefix = row["bssid"][:14]
            sibling = cycle_by_prefix.get(prefix)
            if sibling:
                owned_beacons.append(BeaconFrame(
                    bssid=row["bssid"], ssid=row["ssid"],
                    channel=row["channel"] or sibling.channel,
                    rssi=sibling.rssi, encryption="",
                    is_probe_resp=False,
                ))

    if not owned_beacons:
        return alerts

    # Build channel stats
    channel_aps = {}  # channel -> set of BSSIDs
    for b in beacons:
        channel_aps.setdefault(b.channel, set()).add(b.bssid)

    channel_clients = {}  # channel -> count of probe requests
    for p in probes:
        channel_clients[p.channel] = channel_clients.get(p.channel, 0) + 1

    # Non-owned RSSI per channel (for noise floor estimation)
    channel_noise = {}  # channel -> list of non-owned RSSI values
    for b in beacons:
        if b.ssid not in owned_ssids and b.rssi and b.rssi != 0:
            channel_noise.setdefault(b.channel, []).append(b.rssi)

    for b in owned_beacons:
        ch = b.channel or 6
        ap_count = len(channel_aps.get(ch, set())) - 1  # exclude self
        client_count = channel_clients.get(ch, 0)

        # Noise floor estimate: average of non-owned RSSIs on this channel
        noise_rssis = channel_noise.get(ch, [])
        noise_floor = round(sum(noise_rssis) / len(noise_rssis)) if noise_rssis else None

        # SNR estimate
        snr = (b.rssi - noise_floor) if (b.rssi and noise_floor) else None

        db.execute(
            "INSERT INTO network_health "
            "(bssid, ssid, rssi, channel, beacon_count_cycle, channel_ap_count, "
            "channel_client_count, noise_floor_est, snr_est) "
            "VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)",
            (b.bssid, b.ssid, b.rssi, ch, ap_count, client_count, noise_floor, snr),
        )

        # Check for degradation: compare to recent baseline
        try:
            baseline = db.execute(
                "SELECT AVG(rssi) as avg_rssi, AVG(channel_ap_count) as avg_congestion "
                "FROM network_health WHERE bssid = ? "
                "AND timestamp >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hour') "
                "AND timestamp < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-5 minutes')",
                (b.bssid,),
            ).fetchone()

            if baseline and baseline["avg_rssi"]:
                avg_rssi = baseline["avg_rssi"]
                # RSSI dropped >10dB from 1hr baseline — log only (health data, not WIDS)
                if b.rssi and (avg_rssi - b.rssi) > 10:
                    logger.info(
                        "HEALTH: AP %s (%s) RSSI dropped: %ddBm -> %ddBm (delta %ddB)",
                        b.bssid, b.ssid, round(avg_rssi), b.rssi, round(avg_rssi - b.rssi),
                    )

            # Channel congestion: log only (visible in Health tab via network_health table)
            if ap_count > 5:
                logger.info(
                    "HEALTH: AP %s (%s) on CH%d: %d competing APs",
                    b.bssid, b.ssid, ch, ap_count,
                )
        except Exception:
            logger.debug("Health baseline check failed for %s", b.bssid, exc_info=True)

    db.commit()

    # Cleanup: prune health data older than 7 days
    try:
        db.execute(
            "DELETE FROM network_health WHERE timestamp < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-7 days')"
        )
        db.commit()
    except Exception:
        pass

    return alerts


# ---------------------------------------------------------------------------
# Main scan loop
# ---------------------------------------------------------------------------

def run_scan_loop(config, db) -> None:
    """Continuous scan loop — detect, log, alert.

    Runs indefinitely, performing scan cycles on the configured interface.
    Sends sd_notify WATCHDOG=1 after each cycle for systemd watchdog.

    Args:
        config: Config dataclass with wifi_interface, scan_interval_sec, etc.
        db: sqlite3.Connection to the events database.
    """
    from ssid_monitor.watchlist import get_active_ssids
    from ssid_monitor.detector import match_probes
    from ssid_monitor.logger import log_detection
    from ssid_monitor.alerter import (
        check_cooldown,
        send_alert,
        record_alert,
        build_detection_payload,
        queue_failed_alert,
        flush_failed_queue,
    )
    from ssid_monitor.notifier import (
        notify_watchlist_match,
        notify_new_device,
    )

    ntfy_topic = getattr(config, "ntfy_topic", None)
    db_path = getattr(config, "db_path", None)

    # New-device alerts are opt-in (off by default — too noisy for most setups)
    from ssid_monitor.db import get_setting
    _new_device_alerts_enabled = get_setting(db, "new_device_alerts", "0") == "1"

    # WPA handshake capture
    from ssid_monitor.handshake import HandshakeTracker
    hs_tracker = HandshakeTracker()

    # LE signature detection
    from ssid_monitor.le_detector import LEDetector
    le_detector = LEDetector(db_path=config.db_path)

    logger.info(
        "Starting scan loop on %s (interval=%ds, cooldown=%dm)",
        config.wifi_interface,
        config.scan_interval_sec,
        config.cooldown_min,
    )

    # Build a sd_notify helper
    def _sd_notify(msg):
        try:
            from systemd.daemon import notify as sd_notify  # type: ignore[import-untyped]
            sd_notify(msg)
        except ImportError:
            pass

    consecutive_empty = 0  # track consecutive zero-packet scans

    while True:
        try:
            # 0. Interface health check — only if previous scans were empty
            #    Avoids disruptive monitor-mode resets when the interface is working.
            if consecutive_empty >= 3:
                if not _check_interface_health(config.wifi_interface):
                    _wait_for_interface(config.wifi_interface, notify_fn=_sd_notify)
                    consecutive_empty = 0

            # 1. Reload active watchlist each cycle
            active_ssids = get_active_ssids(db)

            if not active_ssids:
                logger.debug("Watchlist empty — scanning but no matches possible")

            # 2. Run one scan cycle (probes + deauths)
            # Determine priority channels: channels used by owned APs get 3x dwell time
            priority_channels = set()
            try:
                owned_channels = db.execute(
                    "SELECT DISTINCT ap.channel FROM access_points ap "
                    "JOIN watchlist w ON ap.ssid = w.ssid "
                    "WHERE w.active = 1 AND w.watch_type = 'owned' AND ap.channel IS NOT NULL"
                ).fetchall()
                priority_channels = {r["channel"] for r in owned_channels}
            except Exception:
                pass
            result = scan_cycle(config.wifi_interface, timeout=config.scan_interval_sec, priority_channels=priority_channels)
            probes = result.probes
            deauths = result.deauths

            # Track consecutive empty scans for health check gating
            total_frames = len(probes) + len(result.beacons) + len(result.auths) + len(deauths)
            if total_frames > 0:
                consecutive_empty = 0
            else:
                consecutive_empty += 1
                if consecutive_empty == 3:
                    logger.warning("3 consecutive empty scans — will check interface health")

            # 3. Log ALL probes to probe_log for the dashboard
            # Only count alert-type SSIDs as matches (not owned)
            try:
                alert_ssids = {r["ssid"] for r in db.execute(
                    "SELECT ssid FROM watchlist WHERE active = 1 AND watch_type = 'alert'"
                ).fetchall()}
            except Exception:
                alert_ssids = active_ssids if active_ssids else set()
            for p in probes:
                is_match = 1 if p.ssid in alert_ssids else 0
                try:
                    db.execute(
                        "INSERT INTO probe_log (ssid, device_mac, rssi, channel, matched) VALUES (?, ?, ?, ?, ?)",
                        (p.ssid, p.device_mac, p.rssi, p.channel, is_match),
                    )
                except Exception:
                    pass
            db.commit()

            # 4. Device tracking — upsert devices + SSID fingerprints
            try:
                new_macs = update_devices(db, probes)
                for mac in new_macs:
                    ssids = [p.ssid for p in probes if p.device_mac == mac]
                    log_security_event(
                        db, event_type="new_device", device_mac=mac,
                        detail=f"SSIDs: {', '.join(ssids[:5])}",
                        rssi=next((p.rssi for p in probes if p.device_mac == mac), 0),
                    )
                    logger.info("NEW DEVICE: %s probing for %s", mac, ssids[:3])
                    # New-device push notifications are opt-in (noisy in most environments)
                    if _new_device_alerts_enabled:
                        try:
                            notify_new_device(mac, ssids, topic=ntfy_topic, db_path=db_path)
                        except Exception:
                            pass
            except Exception:
                logger.exception("Error in device tracking")

            # 5. Presence detection — arrive / depart
            try:
                check_presence(db, probes)
            except Exception:
                logger.exception("Error in presence detection")

            # 6. Deauth / security event processing (notifications via WIDS in 6b)
            try:
                if deauths:
                    process_deauths(db, deauths)
            except Exception:
                logger.exception("Error processing deauths")

            # 6b. WIDS: AP inventory + threat detection
            try:
                beacons = result.beacons
                auths = result.auths

                # Update AP inventory
                update_access_points(db, beacons)

                # Auto-trust APs broadcasting owned SSIDs
                try:
                    owned_ssids = {r["ssid"] for r in db.execute(
                        "SELECT ssid FROM watchlist WHERE active = 1 AND watch_type = 'owned'"
                    ).fetchall()}
                    if owned_ssids and beacons:
                        for b in beacons:
                            if b.ssid in owned_ssids:
                                db.execute(
                                    "UPDATE access_points SET is_trusted = 1 WHERE bssid = ? AND is_trusted = 0",
                                    (b.bssid,),
                                )
                        db.commit()
                except Exception:
                    pass

                # Run WIDS detectors (real threats only — no infra noise)
                wids_alerts = []
                wids_alerts.extend(detect_evil_twin(db, beacons))
                wids_alerts.extend(detect_karma(db, beacons))
                wids_alerts.extend(track_associations(db, auths))
                wids_alerts.extend(detect_deauth_attack(db, deauths, auths))

                # Send ntfy notifications for critical/high WIDS alerts
                if wids_alerts:
                    from ssid_monitor.notifier import notify_wids_alert
                    for alert in wids_alerts:
                        try:
                            notify_wids_alert(
                                alert_type=alert["alert_type"],
                                severity=alert["severity"],
                                detail=alert["detail"],
                                topic=ntfy_topic,
                                db_path=db_path,
                            )
                        except Exception:
                            pass
                    logger.warning("WIDS: %d alerts raised this cycle", len(wids_alerts))
            except Exception:
                logger.exception("Error in WIDS detection")

            # 6c. Network health monitoring
            try:
                health_alerts = record_health_snapshot(db, beacons, probes)
                if health_alerts:
                    from ssid_monitor.notifier import notify_health_degradation
                    for alert in health_alerts:
                        try:
                            notify_health_degradation(
                                alert_type=alert["alert_type"],
                                detail=alert["detail"],
                                topic=ntfy_topic,
                                db_path=db_path,
                            )
                        except Exception:
                            pass
            except Exception:
                logger.exception("Error in health monitoring")

            # 6d. WPA handshake capture (passive EAPOL collection)
            try:
                for b in result.beacons:
                    if b.ssid:
                        hs_tracker.update_essid(b.bssid, b.ssid)
                for pkt, ap, sta in result.eapol_packets:
                    captured = hs_tracker.add_eapol(pkt, ap, sta)
                    if captured:
                        logger.info(
                            "WPA handshake captured: %s (%s)",
                            captured["essid"], captured["ap_mac"],
                        )
                hs_tracker.cleanup_stale()
            except Exception:
                logger.exception("Error in handshake capture")

            # 6e. LE signature detection (probes first — primary early-warning signal)
            try:
                le_events = le_detector.process_probes(probes)
                le_events.extend(le_detector.process_beacons(result.beacons))
                if le_events:
                    logger.info(
                        "LE DETECTION: %d signatures this cycle (%s)",
                        len(le_events),
                        ", ".join(f"{e.confidence}:{e.mac}" for e in le_events[:3]),
                    )
                # Periodic cleanup of stale in-memory state
                le_detector.cleanup_stale_state()
            except Exception:
                logger.exception("Error in LE detection")

            # 7. Match probed SSIDs against watchlist
            matches = match_probes(probes, active_ssids)

            # 8. Process each match — alert pipeline
            for probe in matches:
                alert_sent = False

                if not check_cooldown(db, probe.ssid):
                    alert_id = record_alert(
                        db,
                        ssid=probe.ssid,
                        device_id=config.device_id,
                        webhook_status=0,
                        webhook_response="pending",
                        cooldown_min=config.cooldown_min,
                    )

                    payload = build_detection_payload(
                        ssid=probe.ssid,
                        device_mac=probe.device_mac,
                        rssi=probe.rssi,
                        channel=probe.channel,
                        device_id=config.device_id,
                        alert_id=alert_id,
                    )

                    status_code, response_text = send_alert(config.webhook_url, payload)

                    db.execute(
                        "UPDATE alerts SET webhook_status = ?, webhook_response = ? WHERE id = ?",
                        (status_code, response_text[:500], alert_id),
                    )
                    db.commit()

                    if status_code == 0:
                        queue_failed_alert(db, payload)
                        logger.warning("Alert queued for retry: %s from %s", probe.ssid, probe.device_mac)
                    else:
                        alert_sent = True
                        logger.info(
                            "ALERT SENT: %s from device %s (RSSI=%d, webhook=%d)",
                            probe.ssid, probe.device_mac, probe.rssi, status_code,
                        )

                    # Push notification via ntfy
                    try:
                        notify_watchlist_match(probe.ssid, probe.device_mac, probe.rssi, probe.channel, topic=ntfy_topic, db_path=db_path)
                    except Exception:
                        pass
                else:
                    logger.debug("Cooldown active for %s — skipping alert", probe.ssid)

                log_detection(
                    db,
                    ssid=probe.ssid,
                    device_id=config.device_id,
                    rssi=probe.rssi,
                    device_mac=probe.device_mac,
                    channel=probe.channel,
                    alert_sent=alert_sent,
                )

            # 9. Flush failed alert queue
            if matches:
                flushed = flush_failed_queue(db, config.webhook_url)
                if flushed:
                    logger.info("Flushed %d queued alerts", flushed)

            # 10. Systemd watchdog heartbeat
            _sd_notify("WATCHDOG=1")

        except KeyboardInterrupt:
            logger.info("Scan loop interrupted — shutting down")
            break
        except Exception:
            logger.exception("Error in scan loop — continuing after next cycle")
            _sd_notify("WATCHDOG=1")
