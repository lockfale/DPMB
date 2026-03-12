"""802.11DPMB (Don't Probe Me Bro) — 802.11 targeted monitoring dashboard."""

import math
import re
import sqlite3
import time

import requests as http_requests
from flask import Flask, jsonify, render_template_string, request

from ssid_monitor.db import get_connection, init_db, get_setting, set_setting, get_all_settings
from ssid_monitor.oui import lookup_vendor

app = Flask(__name__)

DB_PATH = "/var/lib/dpmb/events.db"

# Load device config for settings defaults (best-effort)
_DEVICE_CONFIG = {}
try:
    from ssid_monitor.config import load_config as _load_cfg
    _c = _load_cfg()
    _DEVICE_CONFIG = {
        "device_name": _c.device_id,
        "wifi_interface": _c.wifi_interface,
        "scan_interval": str(_c.scan_interval_sec),
        "cooldown_min": str(_c.cooldown_min),
    }
except Exception:
    pass

# ---------------------------------------------------------------------------
# LE / Government signatures — imported from shared module
# ---------------------------------------------------------------------------
from ssid_monitor.le_signatures import LE_SSID_COMPILED, LE_OUI_FLAT as LE_OUI_PREFIXES

_LE_COMPILED = [(pat, label) for pat, label, _ in LE_SSID_COMPILED]


def classify_probe(ssid: str, device_mac: str) -> tuple[str, str]:
    """Classify a probe as 'match', 'le', or 'probe'. Returns (tag, detail)."""
    for pattern, label in _LE_COMPILED:
        if pattern.search(ssid):
            return ("le", label)

    oui = device_mac[:8].lower() if device_mac else ""
    if oui in LE_OUI_PREFIXES:
        return ("le", LE_OUI_PREFIXES[oui])

    return ("probe", "")


# ---------------------------------------------------------------------------
# LE SSID Auto-Discovery — OUI prefixes, scoring, and API helpers
# ---------------------------------------------------------------------------

LE_DISCOVER_OUI_PREFIXES = {
    "00:90:7a": "Cradlepoint",
    "00:30:44": "Cradlepoint",
    "00:1a:77": "Motorola Solutions",
    "00:19:2c": "Motorola Solutions",
    "00:14:9a": "Motorola Solutions",
    "00:0c:e5": "Motorola Solutions",
    "00:a0:92": "Sierra Wireless",
    "00:14:3e": "Sierra Wireless",
    "9c:28:40": "Sierra Wireless",
    "00:08:a2": "L3Harris",
    "00:01:f4": "L3Harris",
    "00:80:45": "Panasonic",
    "00:0b:97": "Panasonic",
    "70:58:12": "Panasonic",
}

_LE_SSID_PATTERNS = [
    "police", "sheriff", "pd", "patrol", "dispatch", "cad", "mdt", "leo",
    "fire", "ems", "rescue", "govt", "municipal", "county", "court", "fed",
    "marshal", "probation",
]

_RESIDENTIAL_PATTERNS = [
    "xfinity", "att", "spectrum", "tmobile", "verizon", "netgear", "linksys",
    "tp-link", "google", "nest", "ring", "comcast", "optimum", "cox",
    "frontier", "centurylink", "guest",
]

# Regex for default router names: all-caps with model-number-like patterns
_DEFAULT_ROUTER_RE = re.compile(r"^[A-Z0-9]+-[A-Z0-9]+(-[A-Z0-9]+)?$")


def _score_ssid_candidate(candidate: dict, facility_count: int) -> tuple[int, list[str]]:
    """Score an SSID candidate for LE/gov likelihood.

    Returns (score, list_of_reasons).
    """
    score = 0
    reasons = []

    ssid = candidate.get("ssid", "")
    bssid = candidate.get("bssid", "")
    encryption = (candidate.get("encryption") or "").lower()
    ssid_lower = ssid.lower()

    # +50 OUI vendor match
    oui = bssid[:8].lower() if bssid and len(bssid) >= 8 else ""
    if oui in LE_DISCOVER_OUI_PREFIXES:
        vendor = LE_DISCOVER_OUI_PREFIXES[oui]
        score += 50
        reasons.append(f"{vendor} OUI")

    # +30 SSID pattern match
    for pattern in _LE_SSID_PATTERNS:
        if pattern in ssid_lower:
            score += 30
            reasons.append(f"Pattern: {pattern}")
            break  # Only count once

    # +20 Enterprise encryption
    if "enterprise" in encryption or "802.1x" in encryption:
        score += 20
        reasons.append("WPA2-Enterprise encryption")

    # +10 Only seen near one facility (dedicated network)
    if facility_count == 1:
        score += 10
        reasons.append("Seen near single facility only")

    # -50 Known residential/commercial SSID
    for rp in _RESIDENTIAL_PATTERNS:
        if rp in ssid_lower:
            score -= 50
            reasons.append(f"Residential pattern: {rp}")
            break

    # -30 Default router name pattern
    if _DEFAULT_ROUTER_RE.match(ssid) and not any(p in ssid_lower for p in _LE_SSID_PATTERNS):
        score -= 30
        reasons.append("Default router name pattern")

    return score, reasons


def _query_overpass(lat: float, lon: float, radius_km: float) -> list[dict]:
    """Query OSM Overpass API for government facilities within a bounding box.

    Returns a list of dicts with keys: name, type, lat, lon.
    """
    # Calculate bounding box from center + radius
    lat_delta = radius_km / 111.0
    lon_delta = radius_km / (111.0 * math.cos(math.radians(lat)))
    south = lat - lat_delta
    north = lat + lat_delta
    west = lon - lon_delta
    east = lon + lon_delta
    bbox = f"{south},{west},{north},{east}"

    query = f"""[out:json][timeout:25];
(
  node["amenity"="police"]({bbox});
  way["amenity"="police"]({bbox});
  relation["amenity"="police"]({bbox});
  node["amenity"="fire_station"]({bbox});
  way["amenity"="fire_station"]({bbox});
  relation["amenity"="fire_station"]({bbox});
  node["amenity"="courthouse"]({bbox});
  way["amenity"="courthouse"]({bbox});
  relation["amenity"="courthouse"]({bbox});
  node["office"="government"]({bbox});
  way["office"="government"]({bbox});
  relation["office"="government"]({bbox});
  node["building"="government"]({bbox});
  way["building"="government"]({bbox});
  relation["building"="government"]({bbox});
);
out center;"""

    try:
        resp = http_requests.get(
            "https://overpass-api.de/api/interpreter",
            params={"data": query},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    facilities = []
    for el in data.get("elements", []):
        tags = el.get("tags", {})

        # Determine lat/lon: nodes have lat/lon directly; ways/relations use center
        if el["type"] == "node":
            f_lat = el.get("lat")
            f_lon = el.get("lon")
        else:
            center = el.get("center", {})
            f_lat = center.get("lat")
            f_lon = center.get("lon")

        if f_lat is None or f_lon is None:
            continue

        # Determine facility type
        f_type = "government"
        amenity = tags.get("amenity", "")
        if amenity in ("police", "fire_station", "courthouse"):
            f_type = amenity
        elif tags.get("office") == "government" or tags.get("building") == "government":
            f_type = "government"

        name = tags.get("name") or tags.get("official_name") or f"Unnamed {f_type}"

        facilities.append({
            "name": name,
            "type": f_type,
            "lat": f_lat,
            "lon": f_lon,
        })

    return facilities


def _query_wigle_facility(
    lat: float, lon: float, api_name: str, api_token: str
) -> list[dict]:
    """Query WiGLE for SSIDs near a single facility location.

    Returns list of dicts with keys: ssid, bssid, encryption, last_seen, channel.
    """
    # +/- 0.001 degrees ~ 100m around facility
    delta = 0.001
    try:
        resp = http_requests.get(
            "https://api.wigle.net/api/v2/network/search",
            params={
                "latrange1": lat - delta,
                "latrange2": lat + delta,
                "longrange1": lon - delta,
                "longrange2": lon + delta,
                "resultsPerPage": 100,
            },
            auth=(api_name, api_token),
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
    except Exception:
        return []

    results = []
    for net in data.get("results", []):
        ssid = net.get("ssid") or ""
        if not ssid:
            continue
        results.append({
            "ssid": ssid,
            "bssid": (net.get("netid") or "").lower(),
            "encryption": (net.get("encryption") or "").lower(),
            "last_seen": net.get("lastupdt") or net.get("lasttime") or "",
            "channel": net.get("channel") or 0,
        })

    return results


# ---------------------------------------------------------------------------
# 802.11 Deauth reason codes (IEEE 802.11-2020 Table 9-49)
# ---------------------------------------------------------------------------
DEAUTH_REASONS = {
    0: "Reserved",
    1: "Unspecified",
    2: "Auth no longer valid",
    3: "Leaving/has left",
    4: "Inactivity",
    5: "AP overloaded",
    6: "Class 2 from non-auth",
    7: "Class 3 from non-assoc",
    8: "Disassoc leaving",
    9: "Not authenticated",
    10: "Power cap unacceptable",
    11: "Supported ch unacceptable",
    12: "BSS transition",
    13: "Invalid IE",
    14: "MIC failure",
    15: "4-Way handshake timeout",
    16: "Group key handshake timeout",
    17: "IE mismatch",
    18: "Group cipher invalid",
    19: "Pairwise cipher invalid",
    20: "AKMP invalid",
    21: "Unsupported RSNE version",
    22: "Invalid RSNE capabilities",
    23: "802.1X auth failed",
    24: "Cipher suite rejected",
    25: "TDLS teardown unreachable",
    26: "TDLS teardown unspecified",
    34: "Disassoc to prevent connection",
    36: "Requesting STA leaving",
    37: "Requesting mechanism refused",
    38: "Mechanism setup unsupported",
    39: "Timeout",
    45: "Peer STA unreach",
    46: "Peer STA no longer in IBSS",
    47: "U-APSD coexistence mismatch",
    52: "Unauthorized access point",
}


def _parse_deauth_detail(detail: str) -> dict:
    """Parse 'target=xx:xx reason=N ch=N' into structured fields."""
    import re
    result = {"target_mac": None, "reason_code": None, "reason_text": None, "channel": None}
    if not detail:
        return result
    m = re.search(r"target=([0-9a-f:]{17})", detail, re.I)
    if m:
        result["target_mac"] = m.group(1)
    m = re.search(r"reason=(\d+)", detail)
    if m:
        code = int(m.group(1))
        result["reason_code"] = code
        result["reason_text"] = DEAUTH_REASONS.get(code, f"Unknown ({code})")
    m = re.search(r"ch=(\d+)", detail)
    if m:
        result["channel"] = int(m.group(1))
    return result


# ---------------------------------------------------------------------------
# HTML — RF monitoring dashboard
# ---------------------------------------------------------------------------

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='6' fill='%230a0a0a'/><circle cx='16' cy='16' r='3' fill='%234ade80'/><path d='M16 8a8 8 0 0 1 0 16' fill='none' stroke='%234ade80' stroke-width='2' opacity='.8'/><path d='M16 4a12 12 0 0 1 0 24' fill='none' stroke='%234ade80' stroke-width='2' opacity='.5'/><path d='M16 0a16 16 0 0 1 0 32' fill='none' stroke='%234ade80' stroke-width='2' opacity='.25'/></svg>">
<title>802.11DPMB</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0a0a0a; color:#c8c8c8; font-family:'SF Mono','Fira Code','Consolas',monospace; font-size:13px; }

  /* Header */
  .hdr { background:#111; border-bottom:1px solid #222; padding:10px 20px; display:flex; justify-content:space-between; align-items:center; }
  .hdr h1 { color:#e0e0e0; font-size:15px; font-weight:600; }
  .hdr .st { color:#9a9a9a; font-size:11px; }
  .hdr .st .lv { color:#4ade80; }

  /* Stats bar */
  .stats { display:flex; gap:16px; padding:10px 20px; background:#0d0d0d; border-bottom:1px solid #1a1a1a; flex-wrap:wrap; }
  .stat { text-align:center; min-width:70px; }
  .stat .n { font-size:20px; font-weight:700; color:#e0e0e0; }
  .stat .l { font-size:10px; color:#9a9a9a; text-transform:uppercase; letter-spacing:1px; margin-top:1px; }
  .stat.al .n { color:#f87171; }
  .stat.le .n { color:#60a5fa; }
  .stat.sec .n { color:#fbbf24; }

  /* Tabs */
  .tabs { display:flex; border-bottom:1px solid #222; background:#0d0d0d; flex-wrap:wrap; }
  .tab { padding:12px 20px; cursor:pointer; color:#8b8b8b; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:1px; border-bottom:2px solid transparent; transition:all .2s; min-height:36px; }
  .tab:hover { color:#9a9a9a; }
  .tab.active { color:#4ade80; border-bottom-color:#4ade80; }
  .tab .badge { display:inline-block; background:#3d3d3d; color:#9a9a9a; border-radius:8px; padding:0 5px; font-size:10px; margin-left:4px; }
  .tab.active .badge { background:#1a3a1a; color:#4ade80; }
  .tab .badge.alert { background:#7f1d1d; color:#fca5a5; }

  /* Tab panels */
  .panel { display:none; padding:0; position:relative; }
  .panel.active { display:block; }

  /* Shared table styles */
  table { width:100%; border-collapse:collapse; }
  th { text-align:left; padding:6px 12px; color:#8b8b8b; font-size:10px; text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid #1a1a1a; position:sticky; top:0; background:#0a0a0a; z-index:1; }
  td { padding:5px 12px; border-bottom:1px solid #111; white-space:nowrap; }
  tr:hover { background:#111; }

  /* Row coloring */
  tr.matched { background:#1a0a0a; }
  tr.matched td { color:#f87171; }
  tr.le { background:#0a1220; }
  tr.le td { color:#60a5fa; }
  tr.sec-new { background:#1a1800; }
  tr.sec-new td { color:#fbbf24; }
  tr.sec-deauth { background:#1a0a1a; }
  tr.sec-deauth td { color:#c084fc; }

  /* Tags — consistent sizing */
  .tag { display:inline-block; padding:2px 8px; border-radius:3px; font-size:10px; font-weight:600; }
  .tag.match { background:#7f1d1d; color:#fca5a5; }
  .tag.le { background:#1e3a5f; color:#93c5fd; }
  .tag.probe { background:#1a1a1a; color:#8b8b8b; }
  .tag.new { background:#713f12; color:#fde68a; }
  .tag.deauth { background:#3b0764; color:#d8b4fe; }
  .tag.arrive { background:#14532d; color:#86efac; }
  .tag.depart { background:#7f1d1d; color:#fca5a5; }

  /* RSSI bar */
  .rb { display:inline-block; height:8px; border-radius:1px; margin-left:4px; vertical-align:middle; }
  .rb.s { background:#4ade80; }
  .rb.m { background:#facc15; }
  .rb.w { background:#9a9a9a; }

  /* Scrollable areas */
  .scroll { max-height:calc(100vh - 200px); overflow-y:auto; }

  /* Watchlist panel */
  .wl-bar { display:flex; gap:0; background:#0d0d0d; border-bottom:1px solid #1a1a1a; padding:8px 20px; align-items:center; }
  .wl-bar .wl-items { display:flex; gap:6px; flex-wrap:wrap; flex:1; }
  .wl-chip { display:inline-flex; align-items:center; gap:4px; background:#1a0a0a; border:1px solid #7f1d1d; border-radius:4px; padding:2px 8px; font-size:11px; color:#f87171; font-weight:600; }
  .wl-chip .x { cursor:pointer; color:#9a9a9a; font-size:10px; }
  .wl-chip .x:hover { color:#f87171; }
  .wl-chip.owned { background:#0a1a0a; border-color:#14532d; color:#4ade80; }
  .tag.mine { background:#14532d; color:#86efac; }
  .wl-add { display:flex; gap:4px; }
  .wl-add input { background:#151515; border:1px solid #3d3d3d; color:#e0e0e0; padding:6px 8px; border-radius:3px; font-family:inherit; font-size:11px; width:160px; min-height:36px; }
  .wl-add input:focus { outline:none; border-color:#4ade80; }
  .wl-add button { background:#1a3a1a; border:1px solid #2d5a2d; color:#4ade80; padding:6px 14px; border-radius:3px; cursor:pointer; font-family:inherit; font-size:11px; font-weight:600; min-height:36px; }
  .wl-add select { background:#151515; border:1px solid #3d3d3d; color:#e0e0e0; padding:6px 6px; border-radius:3px; font-family:inherit; font-size:11px; min-height:36px; }

  /* Device cards */
  .dev-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(340px, 1fr)); gap:8px; padding:12px 20px; }
  .dev-card { background:#111; border:1px solid #222; border-radius:6px; padding:10px 14px; }
  .dev-card.known { border-color:#14532d; }
  .dev-card.new-dev { border-color:#713f12; border-style:dashed; }
  .dev-card .mac { color:#9a9a9a; font-size:11px; }
  .dev-card .label-name { color:#4ade80; font-weight:700; font-size:15px; }
  .dev-card .meta { color:#8b8b8b; font-size:11px; margin-top:4px; line-height:1.6; }
  .dev-card .ssids { margin-top:6px; display:flex; flex-wrap:wrap; gap:3px; }
  .dev-card .ssid-chip { background:#1a1a1a; border:1px solid #222; border-radius:3px; padding:2px 8px; font-size:10px; color:#9a9a9a; }
  .dev-card .ssid-chip.watched { background:#1a0a0a; border-color:#7f1d1d; color:#f87171; }
  .dev-card .ssid-chip.owned-ssid { background:#0a1a0a; border-color:#14532d; color:#4ade80; }
  .dev-card .actions { margin-top:6px; display:flex; gap:6px; }
  .dev-card .actions input { background:#0a0a0a; border:1px solid #3d3d3d; color:#e0e0e0; padding:6px 8px; border-radius:3px; font-family:inherit; font-size:11px; width:100px; min-height:36px; }
  .dev-card .actions button { background:#1a1a1a; border:1px solid #3d3d3d; color:#9a9a9a; padding:6px 14px; border-radius:3px; cursor:pointer; font-family:inherit; font-size:10px; min-height:36px; }
  .dev-card .actions button:hover { color:#4ade80; border-color:#4ade80; }

  /* Section headers inside panels */
  .sec-hdr { padding:8px 20px; color:#8b8b8b; font-size:10px; text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid #1a1a1a; }

  /* Click-to-add */
  .click-add { cursor:pointer; text-decoration:underline dotted; text-underline-offset:2px; }
  .click-add:hover { color:#4ade80 !important; }

  /* Toast */
  .toast { position:fixed; top:16px; right:16px; background:#1a3a1a; border:1px solid #2d5a2d; color:#4ade80; padding:8px 16px; border-radius:4px; font-size:13px; opacity:0; transition:opacity .3s; z-index:100; }
  .toast.show { opacity:1; }
  .toast.error { background:#3a1a1a; border-color:#5a2d2d; color:#f87171; }


  /* Sparkline */
  .spark { display:inline-block; vertical-align:middle; }
  .spark svg { display:block; }


  /* Fingerprint groups */
  .fp-groups { padding:8px 20px; }
  .fp-group { background:#111; border:1px solid #222; border-radius:6px; padding:10px 14px; margin-bottom:8px; }
  .fp-group .fp-title { color:#c084fc; font-weight:700; font-size:13px; margin-bottom:4px; }
  .fp-group .fp-devices { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:4px; }
  .fp-group .fp-dev { background:#1a1a1a; border:1px solid #3d3d3d; border-radius:3px; padding:2px 8px; font-size:11px; color:#9a9a9a; }
  .fp-group .fp-dev .fp-label { color:#4ade80; font-weight:600; }
  .fp-group .fp-shared { font-size:10px; color:#8b8b8b; }

  /* WIDS */
  .tag.critical { background:#7f1d1d; color:#fca5a5; }
  .tag.high { background:#78350f; color:#fde68a; }
  .tag.medium { background:#1e3a5f; color:#93c5fd; }
  .tag.low { background:#1a1a1a; color:#9a9a9a; }
  .tag.trusted { background:#14532d; color:#86efac; }
  .tag.untrusted { background:#1a1a1a; color:#9a9a9a; }
  .ack-btn { background:#1a1a1a; border:1px solid #3d3d3d; color:#9a9a9a; padding:6px 14px; border-radius:3px; cursor:pointer; font-family:inherit; font-size:10px; min-height:36px; }
  .ack-btn:hover { color:#4ade80; border-color:#4ade80; }
  .trust-btn { background:#1a1a1a; border:1px solid #3d3d3d; color:#9a9a9a; padding:6px 14px; border-radius:3px; cursor:pointer; font-family:inherit; font-size:10px; min-height:36px; }
  .trust-btn:hover { color:#4ade80; border-color:#4ade80; }

  /* Health tab */
  .health-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(280px, 1fr)); gap:8px; padding:12px 20px; }
  .health-card { background:#111; border:1px solid #222; border-radius:6px; padding:12px 14px; }
  .health-card.good { border-color:#14532d; }
  .health-card.warn { border-color:#713f12; }
  .health-card.bad { border-color:#7f1d1d; }
  .health-card .hc-title { font-size:11px; color:#9a9a9a; margin-bottom:4px; }
  .health-card .hc-value { font-size:20px; font-weight:700; }
  .health-card .hc-value.good { color:#4ade80; }
  .health-card .hc-value.warn { color:#facc15; }
  .health-card .hc-value.bad { color:#f87171; }
  .health-card .hc-sub { font-size:10px; color:#8b8b8b; margin-top:2px; }
  .health-chart { padding:8px 20px; }
  .health-chart canvas { width:100%; height:250px; background:#0d0d0d; border:1px solid #1a1a1a; border-radius:4px; }

  /* Watchlist detail */
  .wl-detail { padding:12px 20px; }
  .wl-entry { background:#111; border:1px solid #222; border-radius:6px; padding:14px; margin-bottom:10px; }
  .wl-entry.alert-entry { border-color:#7f1d1d; }
  .wl-entry.owned-entry { border-color:#14532d; }
  .wl-entry .wl-name { font-size:15px; font-weight:700; }
  .wl-entry.alert-entry .wl-name { color:#f87171; }
  .wl-entry.owned-entry .wl-name { color:#4ade80; }
  .wl-entry .wl-status { font-size:13px; margin-top:6px; }
  .wl-entry .wl-status.no-hits { color:#8b8b8b; }
  .wl-entry .wl-status.has-hits { color:#f87171; font-weight:700; }
  .wl-entry .wl-probes { margin-top:8px; }
  .wl-entry .wl-probe-row { display:flex; gap:12px; padding:3px 0; border-bottom:1px solid #1a1a1a; font-size:11px; align-items:center; }
  .wl-entry .wl-probe-row .wl-p-mac { color:#9a9a9a; width:140px; }
  .wl-entry .wl-probe-row .wl-p-vendor { color:#60a5fa; font-size:10px; flex:1; }
  .wl-entry .wl-probe-row .wl-p-rssi { color:#9a9a9a; width:100px; }
  .wl-entry .wl-probe-row .wl-p-time { color:#8b8b8b; width:80px; text-align:right; }

  /* Neighbors */
  .nb-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(320px, 1fr)); gap:8px; padding:12px 20px; }
  .nb-card { background:#111; border:1px solid #222; border-radius:6px; padding:10px 14px; }
  .nb-card.same-ch { border-color:#713f12; }
  .nb-card.le-nb { border-color:#1e3a5f; }
  .nb-card.new-nb { border-color:#4ade80; border-style:dashed; }
  .nb-card .nb-ssid { font-size:15px; font-weight:700; color:#e0e0e0; }
  .nb-card .nb-bssid { color:#8b8b8b; font-size:11px; }
  .nb-card .nb-meta { color:#9a9a9a; font-size:11px; margin-top:4px; }
  .nb-card .nb-tags { margin-top:4px; display:flex; gap:4px; flex-wrap:wrap; }
  .tag.same-ch { background:#78350f; color:#fde68a; }
  .tag.new-ap { background:#14532d; color:#86efac; }
  .tag.hidden-ap { background:#1a1a1a; color:#9a9a9a; font-style:italic; }

  .footer { padding:6px 20px; color:#3d3d3d; font-size:10px; text-align:center; border-top:1px solid #1a1a1a; }

  /* Loading states */
  .loading { opacity:0.5; pointer-events:none; position:relative; min-height:60px; }
  .loading::after { content:'Loading...'; position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); color:#9a9a9a; font-size:13px; }

  /* Search/filter inputs */
  .panel-search { display:flex; gap:8px; padding:8px 20px; background:#0d0d0d; border-bottom:1px solid #1a1a1a; align-items:center; flex-wrap:wrap; }
  .panel-search input, .panel-search select { background:#151515; border:1px solid #3d3d3d; color:#e0e0e0; padding:6px 10px; border-radius:3px; font-family:inherit; font-size:11px; min-height:36px; }
  .panel-search input { flex:1; min-width:200px; max-width:400px; }
  .panel-search input:focus { outline:none; border-color:#4ade80; }
  .panel-search select { min-width:120px; }
  .panel-search label { color:#8b8b8b; font-size:10px; text-transform:uppercase; letter-spacing:1px; }

  /* Responsive — screens under 768px */
  @media (max-width: 768px) {
    .stats { flex-direction:column; align-items:stretch; gap:8px; }
    .stat { display:flex; justify-content:space-between; align-items:center; min-width:auto; text-align:left; }
    .stat .n { font-size:15px; }
    .stat .l { font-size:10px; margin-top:0; }
    table { font-size:11px; }
    th, td { padding:4px 6px; }
    .dev-grid, .nb-grid, .health-grid { grid-template-columns:1fr; padding:8px 10px; }
    .hdr { padding:8px 10px; }
    .stats { padding:8px 10px; }
    .wl-bar { flex-direction:column; gap:8px; padding:8px 10px; }
    .panel-search { padding:8px 10px; }
    .panel-search input { max-width:100%; }
    .sec-hdr { padding:8px 10px; }
    .wl-detail { padding:8px 10px; }
    .fp-groups { padding:8px 10px; }
    .health-chart { padding:8px 10px; }
    .tabs { overflow-x:auto; flex-wrap:nowrap; }
    .tab { padding:10px 12px; font-size:10px; white-space:nowrap; }
  }

  /* Settings gear */
  .gear-btn { background:none; border:none; color:#8b8b8b; font-size:18px; cursor:pointer; padding:4px 8px; transition:color .2s; }
  .gear-btn:hover { color:#4ade80; }

  /* Settings drawer */
  .settings-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.5); z-index:400; }
  .settings-overlay.open { display:block; }
  .settings-drawer { position:fixed; top:0; right:-360px; width:350px; height:100%; background:#111; border-left:1px solid #222; z-index:401; transition:right .3s ease; overflow-y:auto; padding:20px; }
  .settings-drawer.open { right:0; }
  .settings-drawer h2 { color:#e0e0e0; font-size:14px; margin-bottom:16px; }
  .settings-drawer h3 { color:#9a9a9a; font-size:11px; text-transform:uppercase; letter-spacing:1px; margin:16px 0 8px; border-bottom:1px solid #222; padding-bottom:4px; }
  .settings-drawer label { display:flex; align-items:center; gap:8px; color:#c8c8c8; font-size:12px; margin-bottom:8px; }
  .settings-drawer input[type="text"] { background:#0a0a0a; border:1px solid #3d3d3d; color:#e0e0e0; padding:6px 8px; border-radius:3px; font-family:inherit; font-size:11px; width:100%; min-height:30px; }
  .settings-drawer input[type="text"]:focus { outline:none; border-color:#4ade80; }
  .settings-field { margin-bottom:10px; }
  .settings-field .field-label { color:#8b8b8b; font-size:10px; text-transform:uppercase; letter-spacing:1px; margin-bottom:3px; }

  /* Toggle switch */
  .toggle { position:relative; width:36px; height:20px; flex-shrink:0; }
  .toggle input { opacity:0; width:0; height:0; }
  .toggle .slider { position:absolute; cursor:pointer; inset:0; background:#3d3d3d; border-radius:10px; transition:.3s; }
  .toggle .slider:before { content:''; position:absolute; height:14px; width:14px; left:3px; bottom:3px; background:#8b8b8b; border-radius:50%; transition:.3s; }
  .toggle input:checked + .slider { background:#14532d; }
  .toggle input:checked + .slider:before { transform:translateX(16px); background:#4ade80; }

  /* Settings buttons */
  .settings-btn { background:#1a1a1a; border:1px solid #3d3d3d; color:#9a9a9a; padding:6px 14px; border-radius:3px; cursor:pointer; font-family:inherit; font-size:11px; min-height:30px; }
  .settings-btn:hover { color:#4ade80; border-color:#4ade80; }
  .settings-btn.primary { background:#1a3a1a; border-color:#2d5a2d; color:#4ade80; }
  .settings-btn.primary:disabled { opacity:0.4; cursor:default; }
  .settings-btn.primary:disabled:hover { color:#4ade80; border-color:#2d5a2d; }
  .settings-actions { display:flex; gap:8px; margin-top:16px; justify-content:flex-end; }

  /* Tour */
  .tour-overlay { display:none; position:fixed; inset:0; z-index:300; pointer-events:none; }
  .tour-overlay.active { display:block; }
  .tour-highlight { position:absolute; z-index:301; box-shadow:0 0 0 4000px rgba(0,0,0,0.6); border-radius:4px; pointer-events:none; }
  .tour-tooltip { position:absolute; z-index:302; background:#111; border:1px solid #4ade80; border-radius:6px; padding:16px; max-width:320px; pointer-events:auto; }
  .tour-tooltip h4 { color:#4ade80; font-size:13px; margin-bottom:6px; }
  .tour-tooltip p { color:#c8c8c8; font-size:12px; line-height:1.5; margin-bottom:12px; }
  .tour-tooltip .tour-step { color:#8b8b8b; font-size:10px; margin-bottom:8px; }
  .tour-tooltip .tour-btns { display:flex; gap:8px; justify-content:flex-end; }
  .tour-tooltip .tour-btns button { background:#1a1a1a; border:1px solid #3d3d3d; color:#9a9a9a; padding:6px 14px; border-radius:3px; cursor:pointer; font-family:inherit; font-size:11px; }
  .tour-tooltip .tour-btns button:hover { color:#4ade80; border-color:#4ade80; }
  .tour-tooltip .tour-btns .tour-next { background:#1a3a1a; border-color:#2d5a2d; color:#4ade80; }
</style>
</head>
<body>

<div id="toast" class="toast"></div>

<header class="hdr">
  <h1>802.11DPMB <span style="font-weight:400;font-size:14px;color:#7a7a7a">Don't Probe Me Bro</span></h1>
  <div class="st">
    <button class="gear-btn" onclick="toggleSettingsDrawer()" title="Settings">&#9881;</button>
    <span class="lv" id="live-dot">&#9679;</span> Live &mdash; <span id="updated"></span>
  </div>
</header>

<!-- Settings Drawer -->
<div class="settings-overlay" id="settings-overlay" onclick="toggleSettingsDrawer()"></div>
<div class="settings-drawer" id="settings-drawer">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <h2 style="margin:0">Settings</h2>
    <button onclick="toggleSettingsDrawer()" style="background:none;border:none;color:#8b8b8b;font-size:20px;cursor:pointer;padding:4px 8px;line-height:1;" title="Close">&times;</button>
  </div>

  <h3>Device</h3>
  <div class="settings-field">
    <div class="field-label">Device Name</div>
    <input type="text" id="set-device-name" placeholder="hostname" oninput="markSettingsDirty()">
  </div>
  <div class="settings-field">
    <div class="field-label">WiFi Interface</div>
    <select id="set-wifi-interface" onchange="markSettingsDirty()" style="background:#0a0a0a;border:1px solid #3d3d3d;color:#e0e0e0;padding:6px 8px;border-radius:3px;font-family:inherit;font-size:11px;width:100%;min-height:30px;">
      <option value="">Auto-detect</option>
    </select>
    <div style="color:#8b8b8b;font-size:10px;margin-top:3px">Leave on Auto-detect to use the first wireless adapter found</div>
  </div>
  <div class="settings-field">
    <div class="field-label">Scan Interval (seconds)</div>
    <input type="text" id="set-scan-interval" placeholder="10" oninput="markSettingsDirty()">
  </div>
  <div class="settings-field">
    <div class="field-label">Alert Cooldown (minutes)</div>
    <input type="text" id="set-cooldown-min" placeholder="60" oninput="markSettingsDirty()">
  </div>
  <div style="color:#8b8b8b;font-size:10px;margin-top:3px">Scanner restart required for device changes to take effect</div>

  <h3>Alerts</h3>
  <label>
    <span class="toggle"><input type="checkbox" id="set-new-device-alerts" onchange="markSettingsDirty()"><span class="slider"></span></span>
    New device notifications
  </label>
  <div style="color:#8b8b8b;font-size:10px;margin-top:3px">Push when an unseen device appears (can be noisy)</div>

  <h3>ntfy.sh</h3>
  <label>
    <span class="toggle"><input type="checkbox" id="set-ntfy-enabled" onchange="markSettingsDirty()"><span class="slider"></span></span>
    Enable ntfy notifications
  </label>
  <div class="settings-field">
    <div class="field-label">Topic</div>
    <input type="text" id="set-ntfy-topic" placeholder="dpmb-alerts" oninput="markSettingsDirty()">
  </div>
  <div class="settings-field">
    <div class="field-label">Server URL</div>
    <input type="text" id="set-ntfy-server" placeholder="https://ntfy.sh" oninput="markSettingsDirty()">
  </div>
  <button class="settings-btn" onclick="testNotification('ntfy')">Test ntfy</button>

  <h3>Pushover</h3>
  <label>
    <span class="toggle"><input type="checkbox" id="set-pushover-enabled" onchange="markSettingsDirty()"><span class="slider"></span></span>
    Enable Pushover notifications
  </label>
  <div class="settings-field">
    <div class="field-label">Your User Key</div>
    <input type="text" id="set-pushover-user-key" placeholder="pushover.net &#8594; Your User Key" oninput="markSettingsDirty()">
  </div>
  <div class="settings-field">
    <div class="field-label">Application API Token</div>
    <input type="text" id="set-pushover-api-token" placeholder="pushover.net/apps &#8594; Create app, copy token" oninput="markSettingsDirty()">
    <div style="color:#8b8b8b;font-size:10px;margin-top:3px">Register an app at pushover.net/apps to get this</div>
  </div>
  <button class="settings-btn" onclick="testNotification('pushover')">Test Pushover</button>

  <h3 style="color:#60a5fa;margin-top:16px">WiGLE</h3>
  <div style="color:#8b8b8b;font-size:10px;margin-bottom:8px">WiGLE API credentials for LE SSID auto-discovery. Get yours at <span style="color:#60a5fa">wigle.net/account</span></div>
  <div class="settings-field">
    <div class="field-label">API Name</div>
    <input type="text" id="set-wigle-name" placeholder="AID..." oninput="markSettingsDirty()">
  </div>
  <div class="settings-field">
    <div class="field-label">API Token</div>
    <input type="text" id="set-wigle-token" placeholder="Token" oninput="markSettingsDirty()" style="-webkit-text-security:disc">
  </div>
  <button class="settings-btn" onclick="testWigle()">Test WiGLE</button>

  <div class="settings-actions">
    <button class="settings-btn primary" id="save-settings-btn" disabled onclick="saveSettings()">Save</button>
  </div>
</div>

<!-- Tour Overlay -->
<div class="tour-overlay" id="tour-overlay">
  <div class="tour-highlight" id="tour-highlight"></div>
  <div class="tour-tooltip" id="tour-tooltip">
    <div class="tour-step" id="tour-step"></div>
    <h4 id="tour-title"></h4>
    <p id="tour-desc"></p>
    <div class="tour-btns">
      <button onclick="endTour()">Skip</button>
      <button class="tour-next" onclick="nextTourStep()">Next</button>
    </div>
  </div>
</div>

<div class="stats" id="stats"></div>

<div class="wl-bar">
  <div class="wl-items" id="wl-chips"></div>
  <div class="wl-add">
    <input type="text" id="add-ssid" placeholder="+ SSID..." onkeydown="if(event.key==='Enter')addSSID()">
    <select id="add-type"><option value="alert">Watch</option><option value="owned">Mine</option></select>
    <input type="text" id="add-label" placeholder="Label..." style="width:90px;display:none">
    <button onclick="addSSID()">Add</button>
  </div>
</div>

<nav class="tabs" role="tablist" aria-label="Dashboard sections">
  <div class="tab active" role="tab" tabindex="0" aria-selected="true" onclick="switchTab('health')">Health</div>
  <div class="tab" role="tab" tabindex="0" aria-selected="false" onclick="switchTab('live')">Live <span class="badge" id="tab-live-n"></span></div>
  <div class="tab" role="tab" tabindex="0" aria-selected="false" onclick="switchTab('wids')">WIDS <span class="badge alert" id="tab-wids-n"></span></div>
  <div class="tab" role="tab" tabindex="0" aria-selected="false" onclick="switchTab('watchlist')">Watchlist <span class="badge alert" id="tab-wl-n"></span></div>
  <div class="tab" role="tab" tabindex="0" aria-selected="false" onclick="switchTab('devices')">Devices <span class="badge" id="tab-dev-n"></span></div>
  <div class="tab" role="tab" tabindex="0" aria-selected="false" onclick="switchTab('timeline')">Timeline</div>
  <div class="tab" role="tab" tabindex="0" aria-selected="false" onclick="switchTab('neighbors')">Neighbors <span class="badge" id="tab-nb-n"></span></div>
  <div class="tab" role="tab" tabindex="0" aria-selected="false" onclick="switchTab('le')">LE Activity <span class="badge alert" id="tab-le-n"></span></div>
</nav>

<main>

<!-- HEALTH TAB -->
<div class="panel active" id="p-health" role="tabpanel">
<div class="sec-hdr">Network Health &mdash; owned AP signal &amp; channel conditions</div>
<div class="health-grid" id="health-cards"></div>
<div class="sec-hdr" style="margin-top:8px">Signal Strength (last 2 hours)</div>
<div class="health-chart"><canvas id="health-rssi-chart" height="250"></canvas></div>
<div class="sec-hdr" style="margin-top:8px">Channel Congestion (last 2 hours)</div>
<div class="health-chart"><canvas id="health-congestion-chart" height="250"></canvas></div>
<div class="sec-hdr" style="margin-top:8px">Network Environment</div>
<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px;">
  <div style="flex:1;min-width:300px;">
    <div style="color:#9a9a9a;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Channel Distribution</div>
    <canvas id="health-channel-chart" height="120" style="width:100%;background:#0d0d0d;border-radius:4px"></canvas>
  </div>
  <div style="flex:1;min-width:300px;">
    <div style="color:#9a9a9a;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Environment Summary</div>
    <div id="health-env-summary" style="background:#0d0d0d;border-radius:4px;padding:12px;font-size:11px;color:#c8c8c8;min-height:96px"></div>
  </div>
</div>
<div class="sec-hdr" style="margin-top:8px">Recent Health Events</div>
<div class="scroll" style="max-height:30vh">
<table>
  <thead><tr><th>Time</th><th>Type</th><th>BSSID</th><th>SSID</th><th>Detail</th></tr></thead>
  <tbody id="health-events"></tbody>
</table>
</div>
</div>

<!-- LIVE TAB -->
<div class="panel" id="p-live" role="tabpanel">
<div class="panel-search">
  <input type="text" id="live-search" placeholder="Filter probes..." oninput="filterLive(this.value)">
</div>
<div class="scroll">
<table>
  <thead><tr><th>Time</th><th>Device</th><th>SSID</th><th>RSSI</th><th>CH</th><th>Tag</th><th>Detail</th></tr></thead>
  <tbody id="feed"></tbody>
</table>
</div>
</div>

<!-- WIDS TAB -->
<div class="panel" id="p-wids" role="tabpanel">
<div class="sec-hdr">Access Points &mdash; beacon inventory (click to trust/untrust)</div>
<div class="panel-search">
  <input type="text" id="ap-search" placeholder="Filter APs..." oninput="filterAPs(this.value)">
</div>
<div class="scroll" style="max-height:40vh">
<table>
  <thead><tr><th>BSSID</th><th>SSID</th><th>CH</th><th>Enc</th><th>Beacons</th><th>RSSI</th><th>First</th><th>Last</th><th>Status</th><th>Label</th></tr></thead>
  <tbody id="ap-feed"></tbody>
</table>
</div>
<div class="sec-hdr" style="margin-top:8px">WIDS Alerts &mdash; threat detections</div>
<div class="scroll" style="max-height:40vh">
<table>
  <thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>BSSID</th><th>Device</th><th>SSID</th><th>Detail</th><th>Ack</th></tr></thead>
  <tbody id="wids-feed"></tbody>
</table>
</div>
</div>

<!-- WATCHLIST TAB -->
<div class="panel" id="p-watchlist" role="tabpanel">
<div class="sec-hdr">Watchlist Detail &mdash; alert SSID monitoring &amp; owned network status</div>
<div class="scroll">
<div class="wl-detail" id="wl-detail"></div>
</div>
</div>

<!-- DEVICES TAB -->
<div class="panel" id="p-devices" role="tabpanel">
<div class="sec-hdr">All tracked devices &mdash; click to label, mark known/unknown</div>
<div class="panel-search">
  <input type="text" id="dev-search" placeholder="Filter by MAC, label, SSID..." oninput="filterDevices(this.value)">
  <label>Sort:</label>
  <select id="dev-sort" onchange="renderDevices()">
    <option value="last_seen">Last Seen</option>
    <option value="first_seen">First Seen</option>
    <option value="probe_count">Probe Count</option>
    <option value="rssi">Signal</option>
    <option value="known">Known First</option>
  </select>
</div>
<div class="scroll">
<div class="dev-grid" id="dev-grid"></div>
</div>
<div class="sec-hdr" style="margin-top:8px">Fingerprint groups &mdash; devices likely owned by same person (shared SSIDs)</div>
<div id="dev-fingerprints" class="fp-groups"></div>
</div>

<!-- TIMELINE TAB -->
<div class="panel" id="p-timeline" role="tabpanel">
<div class="sec-hdr">Presence events &mdash; arrive / depart</div>
<div class="scroll">
<table>
  <thead><tr><th>Time</th><th>Device</th><th>Label</th><th>Event</th><th>RSSI</th><th>SSID</th><th>Dwell</th></tr></thead>
  <tbody id="timeline-feed"></tbody>
</table>
</div>
</div>

<!-- NEIGHBORS TAB -->
<div class="panel" id="p-neighbors" role="tabpanel">
<div class="sec-hdr">Nearby Access Points &mdash; non-owned APs in range (yellow = same channel as you)</div>
<div class="panel-search">
  <input type="text" id="nb-search" placeholder="Filter by SSID, BSSID, channel..." oninput="filterNeighbors(this.value)">
</div>
<div class="scroll">
<div class="nb-grid" id="nb-grid"></div>
</div>
</div>

<!-- LE ACTIVITY TAB -->
<div class="panel" id="p-le" role="tabpanel">
<div class="sec-hdr">LE / EMS / Fire -- First Responder Scanner Intelligence</div>
<div class="sec-hdr" style="margin-top:8px">Auto-Discover LE/Gov SSIDs</div>
<div style="padding:8px 20px;">
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
    <input type="text" id="discover-address" placeholder="Address, city, or zip code..." style="width:260px;background:#151515;border:1px solid #3d3d3d;color:#e0e0e0;padding:6px 8px;border-radius:3px;font-family:inherit;font-size:11px;min-height:36px" value="" onkeydown="if(event.key==='Enter')discoverLE()">
    <select id="discover-radius" style="background:#151515;border:1px solid #3d3d3d;color:#e0e0e0;padding:6px 6px;border-radius:3px;font-family:inherit;font-size:11px;min-height:36px">
      <option value="5">5 km</option>
      <option value="10" selected>10 km</option>
      <option value="25">25 km</option>
      <option value="50">50 km</option>
    </select>
    <button onclick="discoverLE()" id="discover-btn" style="background:#1a3a1a;border:1px solid #2d5a2d;color:#4ade80;padding:6px 14px;border-radius:3px;cursor:pointer;font-family:inherit;font-size:11px;font-weight:600;min-height:36px">Discover</button>
    <span id="discover-status" style="color:#8b8b8b;font-size:11px"></span>
  </div>
  <div id="discover-results" style="margin-top:8px"></div>
</div>
<div class="wl-bar" style="border-bottom:1px solid #1a1a1a">
  <div class="wl-items" id="gov-chips"></div>
  <div class="wl-add">
    <input type="text" id="gov-ssid" placeholder="+ Gov SSID..." onkeydown="if(event.key==='Enter')addGovSSID()">
    <select id="gov-cat"><option value="leo">LEO</option><option value="ems">EMS</option><option value="fire">Fire</option><option value="govt">Govt</option><option value="other">Other</option></select>
    <input type="text" id="gov-label" placeholder="Label..." style="width:100px">
    <button onclick="addGovSSID()">Add</button>
  </div>
</div>
<div class="panel-search">
  <input id="le-search" type="text" placeholder="Filter by MAC, vendor, SSID..." oninput="filterLE()" style="min-width:220px">
</div>
<div class="health-grid" id="le-entity-cards"></div>
<div class="sec-hdr" style="margin-top:12px">Signal Trajectory -- Approach / Retreat Analysis</div>
<div class="health-chart"><canvas id="le-trajectory-chart" height="250"></canvas></div>
<div class="sec-hdr" style="margin-top:12px">Detection Log (last 24h)</div>
<div class="scroll" style="max-height:40vh">
<table>
  <thead><tr><th>Time</th><th>MAC</th><th>SSID</th><th>Confidence</th><th>Source</th><th>Trend</th><th>RSSI</th><th>CH</th><th>Detail</th></tr></thead>
  <tbody id="le-feed"></tbody>
</table>
</div>
</div>


</main>

<div class="footer">802.11DPMB v0.3.0 &mdash; Don't Probe Me Bro</div>

<script>
let watchedSSIDs = new Set();
let ownedSSIDs = new Set();
let currentTab = 'health';
let cachedDevicesData = null;

const TAB_ORDER = ['health','live','wids','watchlist','devices','timeline','neighbors','le'];

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => {
    const isActive = TAB_ORDER[i] === name;
    t.classList.toggle('active', isActive);
    t.setAttribute('aria-selected', isActive ? 'true' : 'false');
  });
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('p-' + name).classList.add('active');
  currentTab = name;
  refresh();
}

// Keyboard navigation for tabs
document.addEventListener('DOMContentLoaded', function() {
  const tablist = document.querySelector('[role="tablist"]');
  if (tablist) {
    tablist.addEventListener('keydown', function(e) {
      const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));
      const current = tabs.findIndex(t => t.classList.contains('active'));
      let next = current;
      if (e.key === 'ArrowRight') { next = (current + 1) % tabs.length; e.preventDefault(); }
      else if (e.key === 'ArrowLeft') { next = (current - 1 + tabs.length) % tabs.length; e.preventDefault(); }
      else if (e.key === 'Enter' || e.key === ' ') { tabs[current].click(); e.preventDefault(); return; }
      else return;
      tabs[next].focus();
      switchTab(TAB_ORDER[next]);
    });
  }
});

// Filter functions
function filterLive(query) {
  query = query.toLowerCase();
  document.querySelectorAll('#feed tr').forEach(tr => {
    tr.style.display = !query || tr.textContent.toLowerCase().includes(query) ? '' : 'none';
  });
}

function filterDevices(query) {
  query = query.toLowerCase();
  document.querySelectorAll('#dev-grid .dev-card').forEach(card => {
    card.style.display = !query || card.textContent.toLowerCase().includes(query) ? '' : 'none';
  });
}

function filterNeighbors(query) {
  query = query.toLowerCase();
  document.querySelectorAll('#nb-grid .nb-card').forEach(card => {
    card.style.display = !query || card.textContent.toLowerCase().includes(query) ? '' : 'none';
  });
}

function filterAPs(query) {
  query = query.toLowerCase();
  document.querySelectorAll('#ap-feed tr').forEach(tr => {
    tr.style.display = !query || tr.textContent.toLowerCase().includes(query) ? '' : 'none';
  });
}

function toast(msg, isErr) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show' + (isErr ? ' error' : '');
  setTimeout(() => t.className = 'toast', 2500);
}

function rb(rssi) {
  const w = Math.max(2, Math.min(80, (rssi + 100) * 1.5));
  const c = rssi > -40 ? 's' : rssi > -65 ? 'm' : 'w';
  return `${rssi} <span class="rb ${c}" style="width:${w}px"></span>`;
}

function ago(ts) {
  if (!ts) return '?';
  const d = (Date.now() - new Date(ts.endsWith('Z') ? ts : ts + 'Z').getTime()) / 1000;
  if (d < 0) return 'now';
  if (d < 60) return Math.floor(d) + 's ago';
  if (d < 3600) return Math.floor(d/60) + 'm ago';
  if (d < 86400) return Math.floor(d/3600) + 'h ago';
  return Math.floor(d/86400) + 'd ago';
}

function dwell(sec) {
  if (!sec || sec < 0) return '-';
  if (sec < 60) return sec + 's';
  if (sec < 3600) return Math.floor(sec/60) + 'm ' + (sec%60) + 's';
  return Math.floor(sec/3600) + 'h ' + Math.floor((sec%3600)/60) + 'm';
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function sparkline(points, w, h) {
  if (!points || points.length < 2) return '';
  const vals = points.map(p => p.rssi);
  const mn = Math.min(...vals), mx = Math.max(...vals);
  const range = mx - mn || 1;
  const step = w / (vals.length - 1);
  let path = '';
  vals.forEach((v, i) => {
    const x = (i * step).toFixed(1);
    const y = (h - ((v - mn) / range) * h).toFixed(1);
    path += (i === 0 ? 'M' : 'L') + x + ',' + y;
  });
  const color = vals[vals.length-1] > -50 ? '#4ade80' : vals[vals.length-1] > -70 ? '#facc15' : '#9a9a9a';
  return `<span class="spark"><svg width="${w}" height="${h}"><path d="${path}" fill="none" stroke="${color}" stroke-width="1.5"/></svg></span>`;
}

async function addSSID(ssid) {
  ssid = ssid || document.getElementById('add-ssid').value.trim();
  if (!ssid) return;
  const watchType = document.getElementById('add-type') ? document.getElementById('add-type').value : 'alert';
  const label = document.getElementById('add-label') ? document.getElementById('add-label').value.trim() : '';
  const body = {ssid, watch_type: watchType};
  if (label) body.label = label;
  const r = await fetch('/api/watchlist', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  const d = await r.json();
  if (d.ok) { toast('Added "' + ssid + '"' + (watchType === 'owned' ? ' as owned' : '')); document.getElementById('add-ssid').value=''; if (document.getElementById('add-label')) document.getElementById('add-label').value=''; refresh(); }
  else toast(d.error, true);
}

async function removeSSID(ssid) {
  const r = await fetch('/api/watchlist', {method:'DELETE', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ssid})});
  const d = await r.json();
  if (d.ok) { toast('Removed "' + ssid + '"'); refresh(); }
  else toast(d.error, true);
}

async function labelDevice(mac, label) {
  const r = await fetch('/api/device/' + encodeURIComponent(mac) + '/label', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({label})});
  const d = await r.json();
  if (d.ok) toast('Labeled ' + mac); else toast(d.error, true);
  refresh();
}

async function toggleKnown(mac, known) {
  const r = await fetch('/api/device/' + encodeURIComponent(mac) + '/known', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({known})});
  const d = await r.json();
  if (d.ok) toast(known ? 'Marked known' : 'Marked unknown'); else toast(d.error, true);
  refresh();
}

async function refresh() {
  try {
    // Always fetch live stats + watchlist
    const sr = await fetch('/api/feed');
    const data = await sr.json();
    watchedSSIDs = new Set(data.watchlist.filter(w => w.watch_type === 'alert').map(w => w.ssid));
    ownedSSIDs = new Set(data.watchlist.filter(w => w.watch_type === 'owned').map(w => w.ssid));

    // Stats bar
    document.getElementById('stats').innerHTML = `
      <div class="stat"><div class="n">${data.total_probes_5m}</div><div class="l">Probes (5m)</div></div>
      <div class="stat"><div class="n">${data.unique_devices_5m}</div><div class="l">Devices</div></div>
      <div class="stat"><div class="n">${data.unique_ssids_5m}</div><div class="l">SSIDs</div></div>
      <div class="stat al"><div class="n">${data.matches_5m}</div><div class="l">Watchlist Hits</div></div>
      <div class="stat le"><div class="n">${data.le_hits_5m}</div><div class="l">LE / EMS</div></div>
      <div class="stat" style="border-left:2px solid #3b0764"><div class="n" style="color:#d8b4fe">${data.randomized_5m || 0}</div><div class="l">Randomized</div></div>
      <div class="stat"><div class="n">${data.total_devices || 0}</div><div class="l">All Devices</div></div>
    `;

    // Watchlist chips
    const wc = document.getElementById('wl-chips');
    wc.innerHTML = data.watchlist.length === 0
      ? '<span style="color:#7a7a7a;font-size:11px">No SSIDs watched</span>'
      : data.watchlist.map(w => {
        const cls = w.watch_type === 'owned' ? ' owned' : '';
        const lbl = w.label ? ` — ${esc(w.label)}` : '';
        return `<span class="wl-chip${cls}">${esc(w.ssid)}${lbl} <span class="x" onclick="removeSSID('${esc(w.ssid).replace(/'/g,"\\'")}')">x</span></span>`;
      }).join('');

    // Tab badges
    document.getElementById('tab-live-n').textContent = data.total_probes_5m || '';
    // Tab-specific data
    if (currentTab === 'live') renderLive(data);
    else if (currentTab === 'watchlist') await renderWatchlist();
    else if (currentTab === 'devices') await renderDevices();
    else if (currentTab === 'timeline') await renderTimeline();
    else if (currentTab === 'neighbors') await renderNeighbors();
    else if (currentTab === 'le') await renderLE();
    else if (currentTab === 'wids') await renderWids();
    else if (currentTab === 'health') await renderHealth();

    document.getElementById('updated').textContent = new Date().toLocaleTimeString();
    document.getElementById('live-dot').style.color = '#4ade80';
  } catch(e) {
    console.error(e);
    document.getElementById('live-dot').style.color = '#f87171';
  }
}

function renderLive(data) {
  const fb = document.getElementById('feed');
  fb.innerHTML = data.probes.map(p => {
    let rc = '', th = '<span class="tag probe">probe</span>';
    if (p.tag === 'match') { rc = 'matched'; th = '<span class="tag match">MATCH</span>'; }
    else if (p.tag === 'mine') { th = '<span class="tag mine">' + (p.detail ? esc(p.detail) : 'mine') + '</span>'; }
    else if (p.tag === 'le') { rc = 'le'; th = '<span class="tag le">LE</span>'; }
    const cl = p.tag === 'probe' ? ` class="click-add" onclick="addSSID('${esc(p.ssid).replace(/'/g,"\\'")}')"` : '';
    const vnd = p.vendor ? `<br><span style="color:#60a5fa;font-size:10px">${esc(p.vendor)}</span>` : '';
    const timeTitle = p.seen_at ? ` title="${esc(p.seen_at)}"` : '';
    const macTitle = p.vendor ? ` title="${esc(p.vendor)}"` : '';
    const rssiTitle = ` title="Signal strength: ${p.rssi} dBm"`;
    return `<tr class="${rc}"><td${timeTitle}>${ago(p.seen_at)}</td><td${macTitle}>${p.device_mac}${vnd}</td><td${cl}>${esc(p.ssid)}</td><td${rssiTitle}>${rb(p.rssi)}</td><td>${p.channel||'?'}</td><td>${th}</td><td style="color:#8b8b8b;font-size:11px">${p.detail?esc(p.detail):''}</td></tr>`;
  }).join('');
}

async function renderWatchlist() {
  const c = document.getElementById('wl-detail');
  c.classList.add('loading');
  const r = await fetch('/api/watchlist/detail');
  const data = await r.json();
  c.classList.remove('loading');
  document.getElementById('tab-wl-n').textContent = data.alert_hits > 0 ? data.alert_hits : '';

  if (data.entries.length === 0) {
    c.innerHTML = '<div style="padding:30px;text-align:center;color:#8b8b8b"><div style="font-size:15px;margin-bottom:8px;color:#9a9a9a">No SSIDs on watchlist</div><div style="font-size:13px">Use the <strong style="color:#4ade80">+ SSID</strong> input above to add SSIDs you want to monitor. Choose <em>Watch</em> for alerts or <em>Mine</em> for owned networks.</div></div>';
    return;
  }

  c.innerHTML = data.entries.map(e => {
    const cls = e.watch_type === 'owned' ? 'owned-entry' : 'alert-entry';
    const typeTag = e.watch_type === 'owned'
      ? '<span class="tag mine">OWNED</span>'
      : '<span class="tag match">WATCHING</span>';
    const labelText = e.label ? ' &mdash; ' + esc(e.label) : '';

    let statusHtml = '';
    if (e.watch_type === 'alert') {
      if (e.total_probes === 0) {
        statusHtml = '<div class="wl-status no-hits">No detections &mdash; this SSID has not been probed by any device in range</div>';
      } else {
        statusHtml = `<div class="wl-status has-hits">${e.total_probes} detection(s) from ${e.unique_devices} device(s) &mdash; last seen ${ago(e.last_seen)}</div>`;
      }
      if (e.recent_probes && e.recent_probes.length > 0) {
        statusHtml += '<div class="wl-probes">' + e.recent_probes.map(p =>
          `<div class="wl-probe-row"><span class="wl-p-mac">${p.device_mac}</span><span class="wl-p-vendor">${p.vendor ? esc(p.vendor) : ''}</span><span class="wl-p-rssi">${rb(p.rssi)}</span><span class="wl-p-time">${ago(p.seen_at)}</span></div>`
        ).join('') + '</div>';
      }
    } else {
      statusHtml = `<div class="wl-status" style="color:#4ade80">${e.ap_count} AP(s) broadcasting this SSID</div>`;
      if (e.aps && e.aps.length > 0) {
        statusHtml += e.aps.map(ap =>
          `<div style="font-size:11px;color:#9a9a9a;margin-top:2px">BSSID: ${ap.bssid} | CH${ap.channel || '?'} | RSSI: ${ap.rssi != null ? ap.rssi + ' dBm' : '?'} | Last: ${ago(ap.last_seen)}</div>`
        ).join('');
      }
    }

    return `<div class="wl-entry ${cls}"><div><span class="wl-name">${esc(e.ssid)}</span> ${typeTag}${labelText}</div>${statusHtml}</div>`;
  }).join('');
}

async function renderDevices() {
  const g = document.getElementById('dev-grid');
  g.classList.add('loading');
  const r = await fetch('/api/devices');
  const data = await r.json();
  g.classList.remove('loading');
  cachedDevicesData = data;
  document.getElementById('tab-dev-n').textContent = data.devices.length || '';

  // Sort devices
  const sortBy = document.getElementById('dev-sort') ? document.getElementById('dev-sort').value : 'last_seen';
  data.devices.sort((a, b) => {
    if (sortBy === 'last_seen') return (b.last_seen || '').localeCompare(a.last_seen || '');
    if (sortBy === 'first_seen') return (b.first_seen || '').localeCompare(a.first_seen || '');
    if (sortBy === 'probe_count') return (b.probe_count || 0) - (a.probe_count || 0);
    if (sortBy === 'rssi') return (b.avg_rssi || -100) - (a.avg_rssi || -100);
    if (sortBy === 'known') return (b.is_known ? 1 : 0) - (a.is_known ? 1 : 0) || (b.last_seen || '').localeCompare(a.last_seen || '');
    return 0;
  });

  // Fetch RSSI sparkline data for top 20 devices
  const sparkPromises = data.devices.slice(0, 20).map(d =>
    fetch('/api/device/' + encodeURIComponent(d.mac) + '/rssi_history').then(r => r.json()).catch(() => ({points:[]}))
  );
  const sparkData = await Promise.all(sparkPromises);
  const sparkMap = {};
  data.devices.slice(0, 20).forEach((d, i) => { sparkMap[d.mac] = sparkData[i].points || []; });

  g.innerHTML = data.devices.map(d => {
    const cls = d.is_known ? ' known' : (d.is_new ? ' new-dev' : '');
    const lbl = d.label ? `<div class="label-name">${esc(d.label)}</div>` : '';
    const knBtn = d.is_known
      ? `<button onclick="toggleKnown('${d.mac}',false)">Mark Unknown</button>`
      : `<button onclick="toggleKnown('${d.mac}',true)">Mark Known</button>`;
    const spark = sparkMap[d.mac] ? sparkline(sparkMap[d.mac], 120, 20) : '';
    const randTag = d.is_randomized ? ' <span class="tag" style="background:#3b0764;color:#d8b4fe">RAND</span>' : '';
    const macTitle = d.vendor ? ` title="${esc(d.vendor)}"` : '';
    const firstTitle = d.first_seen ? ` title="${esc(d.first_seen)}"` : '';
    const lastTitle = d.last_seen ? ` title="${esc(d.last_seen)}"` : '';
    const rssiTitle = d.avg_rssi ? ` title="Signal strength: ${d.avg_rssi} dBm avg"` : '';
    return `<div class="dev-card${cls}">
      ${lbl}<div class="mac"${macTitle}>${d.mac}${randTag}${d.vendor ? ' <span style="color:#60a5fa;font-size:10px">' + esc(d.vendor) + '</span>' : ''}</div>
      <div class="meta"><span${firstTitle}>First: ${ago(d.first_seen)}</span> | <span${lastTitle}>Last: ${ago(d.last_seen)}</span> | Probes: ${d.probe_count}<br><span${rssiTitle}>RSSI: ${d.avg_rssi||'?'} avg (${d.min_rssi||'?'} to ${d.max_rssi||'?'})</span> ${spark}</div>
      <div class="ssids">${(d.ssids||[]).map(s => `<span class="ssid-chip${ownedSSIDs.has(s)?' owned-ssid':watchedSSIDs.has(s)?' watched':''}" title="${esc(s)}">${esc(s)}</span>`).join('')}</div>
      <div class="actions">
        <input placeholder="Label..." value="${d.label||''}" onkeydown="if(event.key==='Enter')labelDevice('${d.mac}',this.value)">
        ${knBtn}
      </div>
    </div>`;
  }).join('');

  // Re-apply filter if active
  const searchVal = document.getElementById('dev-search') ? document.getElementById('dev-search').value : '';
  if (searchVal) filterDevices(searchVal);

  // Fingerprint groups (devices sharing 2+ SSIDs = likely same owner)
  try {
    const fp = await fetch('/api/fingerprint_groups');
    const fpData = await fp.json();
    const fpEl = document.getElementById('dev-fingerprints');
    if (fpData.groups.length === 0) {
      fpEl.innerHTML = '<div style="padding:8px 0;color:#7a7a7a">No fingerprint groups detected yet (need devices with 2+ shared SSIDs)</div>';
    } else {
      fpEl.innerHTML = fpData.groups.map(g => {
        const devs = g.devices.map(d => {
          const lbl = d.label ? `<span class="fp-label">${esc(d.label)}</span> ` : '';
          const vnd = d.vendor ? `<span style="color:#60a5fa">${esc(d.vendor)}</span> ` : '';
          return `<span class="fp-dev">${lbl}${vnd}${d.mac}</span>`;
        }).join('');
        return `<div class="fp-group">
          <div class="fp-title">Group (${g.devices.length} devices, ${Math.round(g.similarity*100)}% overlap)</div>
          <div class="fp-devices">${devs}</div>
          <div class="fp-shared">Shared SSIDs: ${g.shared_ssids.map(s => esc(s)).join(', ')}</div>
        </div>`;
      }).join('');
    }
  } catch(e) { console.error('fingerprints', e); }
}

async function renderTimeline() {
  const r = await fetch('/api/timeline');
  const data = await r.json();
  const tb = document.getElementById('timeline-feed');
  tb.innerHTML = data.events.map(e => {
    const tc = e.event_type === 'arrive' ? 'arrive' : 'depart';
    return `<tr><td>${ago(e.timestamp)}</td><td>${e.device_mac}</td><td>${e.label?esc(e.label):''}</td><td><span class="tag ${tc}">${e.event_type}</span></td><td>${e.rssi?rb(e.rssi):'-'}</td><td>${e.ssid?esc(e.ssid):''}</td><td>${dwell(e.dwell_sec)}</td></tr>`;
  }).join('');
}

async function renderNeighbors() {
  const g = document.getElementById('nb-grid');
  g.classList.add('loading');
  const r = await fetch('/api/neighbors');
  const data = await r.json();
  g.classList.remove('loading');
  document.getElementById('tab-nb-n').textContent = data.neighbors.length || '';

  if (data.neighbors.length === 0) {
    g.innerHTML = '<div style="padding:20px;color:#7a7a7a">No neighbor APs detected yet</div>';
    return;
  }

  g.innerHTML = data.neighbors.map(n => {
    const tags = [];
    if (n.same_channel) tags.push('<span class="tag same-ch">YOUR CH</span>');
    if (n.is_le) tags.push('<span class="tag le">' + esc(n.le_detail) + '</span>');
    if (n.is_new) tags.push('<span class="tag new-ap">NEW</span>');
    if (!n.ssid) tags.push('<span class="tag hidden-ap">hidden</span>');

    const cls = n.is_le ? ' le-nb' : (n.same_channel ? ' same-ch' : (n.is_new ? ' new-nb' : ''));
    const vendor = n.vendor ? `<span style="color:#60a5fa;font-size:10px">${esc(n.vendor)}</span>` : '';
    const spark = n.rssi_history ? sparkline(n.rssi_history, 100, 16) : '';
    const rssiTitle = n.avg_rssi ? ` title="Signal strength: ${Math.round(n.avg_rssi)} dBm"` : '';
    const bssidTitle = n.vendor ? ` title="${esc(n.vendor)}"` : '';
    const firstTitle = n.first_seen ? ` title="${esc(n.first_seen)}"` : '';
    const lastTitle = n.last_seen ? ` title="${esc(n.last_seen)}"` : '';

    return `<div class="nb-card${cls}">
      <div class="nb-ssid" title="${n.ssid ? esc(n.ssid) : 'Hidden network'}">${n.ssid ? esc(n.ssid) : '(hidden)'}</div>
      <div class="nb-bssid"${bssidTitle}>${n.bssid} ${vendor}</div>
      <div class="nb-meta">CH${n.channel||'?'} | ${esc(n.encryption)} | ${n.beacon_count} beacons | <span${rssiTitle}>RSSI: ${n.avg_rssi ? Math.round(n.avg_rssi) : '?'}</span> ${spark}</div>
      <div class="nb-meta"><span${firstTitle}>First: ${ago(n.first_seen)}</span> | <span${lastTitle}>Last: ${ago(n.last_seen)}</span></div>
      <div class="nb-tags">${tags.join('')}</div>
    </div>`;
  }).join('');

  // Re-apply filter if active
  const searchVal = document.getElementById('nb-search') ? document.getElementById('nb-search').value : '';
  if (searchVal) filterNeighbors(searchVal);
}


async function renderWids() {
  // AP inventory
  const apFeed = document.getElementById('ap-feed');
  apFeed.closest('.scroll').classList.add('loading');
  const apr = await fetch('/api/access_points');
  const apData = await apr.json();
  apFeed.closest('.scroll').classList.remove('loading');
  apFeed.innerHTML = apData.access_points.map(ap => {
    const trustTag = ap.is_trusted ? '<span class="tag trusted">trusted</span>' : '<span class="tag untrusted">untrusted</span>';
    const trustBtn = ap.is_trusted
      ? `<button class="trust-btn" onclick="trustAP('${ap.bssid}',false)">Untrust</button>`
      : `<button class="trust-btn" onclick="trustAP('${ap.bssid}',true)">Trust</button>`;
    const timeTitle1 = ap.first_seen ? ` title="${esc(ap.first_seen)}"` : '';
    const timeTitle2 = ap.last_seen ? ` title="${esc(ap.last_seen)}"` : '';
    const rssiTitle = ap.avg_rssi ? ` title="Signal strength: ${Math.round(ap.avg_rssi)} dBm"` : '';
    return `<tr><td>${ap.bssid}</td><td>${esc(ap.ssid||'(hidden)')}</td><td>${ap.channel||'?'}</td><td>${esc(ap.encryption)}</td><td>${ap.beacon_count}</td><td${rssiTitle}>${ap.avg_rssi?Math.round(ap.avg_rssi):'-'}</td><td${timeTitle1}>${ago(ap.first_seen)}</td><td${timeTitle2}>${ago(ap.last_seen)}</td><td>${trustTag} ${trustBtn}</td><td>${ap.label?esc(ap.label):''}</td></tr>`;
  }).join('') || '<tr><td colspan="10" style="color:#7a7a7a;text-align:center;padding:20px">No APs detected yet — beacons will appear here</td></tr>';

  // Re-apply filter if active
  const apSearchVal = document.getElementById('ap-search') ? document.getElementById('ap-search').value : '';
  if (apSearchVal) filterAPs(apSearchVal);

  // WIDS alerts
  const wr = await fetch('/api/wids_alerts');
  const wData = await wr.json();
  document.getElementById('tab-wids-n').textContent = wData.unacknowledged || '';
  document.getElementById('wids-feed').innerHTML = wData.alerts.map(a => {
    const sevTag = `<span class="tag ${a.severity}">${a.severity}</span>`;
    const ackBtn = a.acknowledged ? '<span style="color:#4ade80">&#10003;</span>' : `<button class="ack-btn" onclick="ackWidsAlert(${a.id})">Ack</button>`;
    const timeTitle = a.seen_at ? ` title="${esc(a.seen_at)}"` : '';
    return `<tr><td${timeTitle}>${ago(a.seen_at)}</td><td>${esc(a.alert_type)}</td><td>${sevTag}</td><td>${a.bssid||''}</td><td>${a.device_mac||''}</td><td>${esc(a.ssid||'')}</td><td style="font-size:11px;color:#9a9a9a">${esc(a.detail||'')}</td><td>${ackBtn}</td></tr>`;
  }).join('') || '<tr><td colspan="8" style="color:#7a7a7a;text-align:center;padding:20px">No WIDS alerts — all clear</td></tr>';
}

async function trustAP(bssid, trust) {
  const r = await fetch('/api/access_points/' + encodeURIComponent(bssid) + '/trust', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({trusted:trust})});
  const d = await r.json();
  if (d.ok) toast(trust ? 'AP trusted' : 'AP untrusted'); else toast(d.error, true);
  refresh();
}

async function ackWidsAlert(id) {
  const r = await fetch('/api/wids_alerts/' + id + '/acknowledge', {method:'POST'});
  const d = await r.json();
  if (d.ok) toast('Alert acknowledged'); else toast(d.error, true);
  refresh();
}

async function renderHealth() {
  const cards = document.getElementById('health-cards');
  cards.classList.add('loading');
  const r = await fetch('/api/health/summary');
  const data = await r.json();
  cards.classList.remove('loading');

  // Status cards per owned BSSID
  if (data.nodes.length === 0) {
    cards.innerHTML = '<div style="padding:8px;color:#7a7a7a">No owned APs configured — add SSIDs as "Mine" to monitor health</div>';
  } else {
    cards.innerHTML = data.nodes.map(n => {
      const rssiClass = n.rssi > -50 ? 'good' : n.rssi > -70 ? 'warn' : 'bad';
      const cardClass = rssiClass;
      const congClass = n.channel_ap_count > 5 ? 'bad' : n.channel_ap_count > 3 ? 'warn' : 'good';
      const snrText = n.snr_est != null ? `SNR: ${n.snr_est}dB` : '';
      return `<div class="health-card ${cardClass}">
        <div class="hc-title">${esc(n.ssid || '?')} &mdash; ${n.bssid}</div>
        <div class="hc-value ${rssiClass}">${n.rssi || '?'} dBm</div>
        <div class="hc-sub">CH${n.channel || '?'} | ${n.channel_ap_count} competing APs | ${n.channel_client_count} clients ${snrText ? '| ' + snrText : ''}</div>
        <div class="hc-sub" style="margin-top:4px">Trend (2h): ${sparkline(n.rssi_history || [], 160, 24)}</div>
      </div>`;
    }).join('');
  }

  // Draw RSSI chart
  drawHealthChart('health-rssi-chart', data.timeline, 'rssi', 'RSSI (dBm)', -100, 0);

  // Draw congestion chart
  drawHealthChart('health-congestion-chart', data.timeline, 'channel_ap_count', 'APs on Channel', 0, 15);

  // Network environment: channel distribution bar chart
  const env = data.environment;
  if (env && env.channels) {
    const cc = document.getElementById('health-channel-chart');
    if (cc) {
      const cctx = cc.getContext('2d');
      const cW = cc.width = cc.offsetWidth;
      const cH = cc.height = 120;
      cctx.clearRect(0, 0, cW, cH);
      cctx.fillStyle = '#0d0d0d';
      cctx.fillRect(0, 0, cW, cH);
      const maxAP = Math.max(1, ...env.channels.map(c => c.ap_count));
      const barW = Math.max(12, (cW - 60) / 14);
      const cPad = {left:35, top:10, bottom:20};
      const plotH = cH - cPad.top - cPad.bottom;
      // Y axis
      cctx.fillStyle = '#7a7a7a'; cctx.font = '10px monospace'; cctx.textAlign = 'right';
      for (let i = 0; i <= 3; i++) {
        const v = Math.round(maxAP * (1 - i/3));
        const y = cPad.top + (i/3) * plotH;
        cctx.fillText(v.toString(), cPad.left - 4, y + 4);
        cctx.strokeStyle = '#1a1a1a'; cctx.lineWidth = 1;
        cctx.beginPath(); cctx.moveTo(cPad.left, y); cctx.lineTo(cW - 10, y); cctx.stroke();
      }
      // Bars
      for (const ch of env.channels) {
        const x = cPad.left + (ch.channel - 1) * barW + 2;
        const h = (ch.ap_count / maxAP) * plotH;
        const y = cPad.top + plotH - h;
        // Color: green for owned channels, blue for others
        const isPrio = data.nodes.some(n => n.channel === ch.channel);
        cctx.fillStyle = isPrio ? '#4ade80' : '#3b82f6';
        cctx.fillRect(x, y, barW - 4, h);
        // Channel label
        cctx.fillStyle = '#9a9a9a'; cctx.font = '9px monospace'; cctx.textAlign = 'center';
        cctx.fillText('CH' + ch.channel, x + (barW - 4) / 2, cH - 4);
        // Count on top of bar
        if (ch.ap_count > 0) {
          cctx.fillStyle = '#e0e0e0'; cctx.font = '9px monospace';
          cctx.fillText(ch.ap_count.toString(), x + (barW - 4) / 2, y - 3);
        }
      }
    }
    // Environment summary
    const sumDiv = document.getElementById('health-env-summary');
    if (sumDiv && env) {
      const busiest = [...env.channels].sort((a,b) => b.ap_count - a.ap_count).slice(0, 3);
      sumDiv.innerHTML = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
          <div><span style="color:#4ade80;font-size:16px;font-weight:bold">${env.total_aps}</span><br><span style="color:#7a7a7a;font-size:10px">Total APs Detected</span></div>
          <div><span style="color:#60a5fa;font-size:16px;font-weight:bold">${env.total_devices}</span><br><span style="color:#7a7a7a;font-size:10px">Total Devices Seen</span></div>
          <div><span style="color:#facc15;font-size:16px;font-weight:bold">${env.probes_1h}</span><br><span style="color:#7a7a7a;font-size:10px">Probes (last hour)</span></div>
          <div><span style="color:#9a9a9a;font-size:16px;font-weight:bold">${busiest.map(c => 'CH' + c.channel).join(', ')}</span><br><span style="color:#7a7a7a;font-size:10px">Busiest Channels</span></div>
        </div>`;
    }
  }

  // Health events
  const evts = data.health_events || [];
  document.getElementById('health-events').innerHTML = evts.length === 0
    ? '<tr><td colspan="5" style="color:#7a7a7a;text-align:center;padding:20px">No health events — network looks good</td></tr>'
    : evts.map(e => {
      const evtTimeTitle = e.seen_at ? ` title="${esc(e.seen_at)}"` : '';
      return `<tr><td${evtTimeTitle}>${ago(e.seen_at)}</td><td><span class="tag medium">${esc(e.alert_type)}</span></td><td>${e.bssid||''}</td><td>${esc(e.ssid||'')}</td><td style="font-size:11px;color:#9a9a9a">${esc(e.detail||'')}</td></tr>`;
    }).join('');
}

// --- Gov SSID management ---
async function loadGovSSIDs() {
  const r = await fetch('/api/gov-ssids');
  const data = await r.json();
  const chips = document.getElementById('gov-chips');
  if (!chips) return;
  const catColor = {leo:'#7f1d1d', ems:'#7f3d1d', fire:'#7f1d3d', govt:'#1d3d7f', other:'#3d3d3d'};
  chips.innerHTML = data.entries.map(e => {
    const bg = catColor[e.category] || '#3d3d3d';
    return '<span class="wl-chip" style="background:' + bg + ';border-color:' + bg + '">' +
      esc(e.ssid) + (e.label ? ' <span style="opacity:.6">(' + esc(e.label) + ')</span>' : '') +
      ' <span class="x" onclick="removeGovSSID(' + e.id + ')" style="cursor:pointer;margin-left:4px">&times;</span></span>';
  }).join('');
}
async function addGovSSID() {
  const ssid = (document.getElementById('gov-ssid')?.value || '').trim();
  if (!ssid) return;
  const category = document.getElementById('gov-cat')?.value || 'govt';
  const label = (document.getElementById('gov-label')?.value || '').trim();
  const r = await fetch('/api/gov-ssids', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ssid, label, category, weight:50})});
  const d = await r.json();
  if (d.ok) { toast('Added gov SSID "' + ssid + '"'); document.getElementById('gov-ssid').value=''; document.getElementById('gov-label').value=''; loadGovSSIDs(); }
  else toast(d.error, true);
}
async function removeGovSSID(id) {
  const r = await fetch('/api/gov-ssids', {method:'DELETE', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id})});
  const d = await r.json();
  if (d.ok) { toast('Removed gov SSID'); loadGovSSIDs(); }
  else toast(d.error, true);
}

// --- LE Activity tab ---
let _leData = null;
async function renderLE() {
  loadGovSSIDs();
  const cards = document.getElementById('le-entity-cards');
  cards.classList.add('loading');
  const r = await fetch('/api/le/activity');
  const data = await r.json();
  _leData = data;
  cards.classList.remove('loading');

  // Tab badge
  const badge = document.getElementById('tab-le-n');
  if (badge) badge.textContent = data.stats.unique_entities_24h || '';

  // Entity cards
  if (data.entities.length === 0) {
    cards.innerHTML = '<div style="padding:20px;color:#7a7a7a;text-align:center">No LE signatures detected in last 24h &mdash; scanner is monitoring all beacons and probes</div>';
  } else {
    const confOrder = {critical:0, high:1, medium:2, low:3};
    const confColor = {critical:'#dc2626', high:'#ea580c', medium:'#ca8a04', low:'#6b7280'};
    cards.innerHTML = data.entities.map(e => {
      const cc = confColor[e.max_confidence] || '#6b7280';
      const traj = data.trajectories[e.mac] || [];
      const rssiArr = traj.map(t => ({rssi: t.rssi}));
      const spark = sparkline(rssiArr, 160, 24);
      const trendIcon = e.trend === 'approaching' ? '&#x2191; APPROACHING' :
                        e.trend === 'departing' ? '&#x2193; departing' : '&#x2014; stable';
      const safeId = e.mac.replace(/:/g, '-');
      return `<div class="health-card" style="border-left:3px solid ${cc}">
        <div class="hc-title" style="color:${cc};cursor:pointer" onclick="toggleProbeFingerprint('${esc(e.mac)}','${safeId}')">${esc(e.mac)} <span style="font-size:10px;color:#7a7a7a">&#9660; probes</span></div>
        <div style="margin:4px 0"><span class="tag" style="background:${cc};color:#fff;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:600">${(e.max_confidence||'').toUpperCase()}</span></div>
        <div class="hc-sub">${e.detection_count} detections | Avg RSSI: ${e.avg_rssi || '?'} dBm</div>
        <div class="hc-sub">SSIDs: ${(e.ssids||[]).map(s => esc(s)).join(', ') || 'none'}</div>
        <div class="hc-sub">First: ${ago(e.first_seen)} | Last: ${ago(e.last_seen)}</div>
        <div class="hc-sub" style="margin-top:4px">Signal: ${spark}</div>
        <div id="probe-fp-${safeId}" class="probe-fingerprint" style="display:none"></div>
      </div>`;
    }).join('');
  }

  // Trajectory chart
  if (data.entities.length > 0) {
    const allTraj = [];
    for (const [mac, pts] of Object.entries(data.trajectories)) {
      pts.forEach(p => allTraj.push({bssid: mac, rssi: p.rssi, timestamp: p.t, channel_ap_count: 0}));
    }
    if (allTraj.length > 0) {
      drawHealthChart('le-trajectory-chart', allTraj, 'rssi', 'RSSI (dBm)', -100, 0);
    }
  }

  // Detection log
  document.getElementById('le-feed').innerHTML = data.detections.length === 0
    ? '<tr><td colspan="9" style="color:#7a7a7a;text-align:center;padding:20px">No LE detections in last 24h</td></tr>'
    : data.detections.map(d => {
      const confColor = {critical:'#dc2626', high:'#ea580c', medium:'#ca8a04', low:'#6b7280'};
      const cc = confColor[d.confidence] || '#6b7280';
      const trendIcon = d.trend === 'approaching' ? '<span style="color:#dc2626">&#x25B2; APPROACHING</span>' :
                        d.trend === 'departing' ? '<span style="color:#4ade80">&#x25BC; departing</span>' :
                        '<span style="color:#7a7a7a">&#x2014; stable</span>';
      return `<tr class="le"><td title="${esc(d.seen_at||'')}">${ago(d.seen_at)}</td><td title="${esc(d.mac)}">${d.mac}</td><td>${esc(d.ssid||'')}</td><td><span class="tag" style="background:${cc};color:#fff">${(d.confidence||'').toUpperCase()}</span></td><td>${d.source_type||''}</td><td>${trendIcon}</td><td>${rb(d.rssi)}</td><td>${d.channel||'?'}</td><td style="font-size:10px;color:#9a9a9a;max-width:300px;overflow:hidden;text-overflow:ellipsis" title="${esc(d.detail||'')}">${esc(d.detail||'')}</td></tr>`;
    }).join('');
}

async function toggleProbeFingerprint(mac, safeId) {
  const el = document.getElementById('probe-fp-' + safeId);
  if (!el) return;
  if (el.style.display !== 'none') { el.style.display = 'none'; return; }
  el.style.display = 'block';
  el.innerHTML = '<div style="padding:8px;color:#7a7a7a;font-size:11px">Loading probe fingerprint...</div>';
  try {
    const r = await fetch('/api/device/' + encodeURIComponent(mac) + '/probes');
    const data = await r.json();
    if (!data.probes || data.probes.length === 0) {
      el.innerHTML = '<div style="padding:8px;color:#7a7a7a;font-size:11px">No probe history for this device</div>';
      return;
    }
    el.innerHTML = '<div style="padding:6px 0 4px;font-size:10px;color:#9a9a9a;text-transform:uppercase;letter-spacing:1px">Probe Fingerprint &mdash; all SSIDs this device has searched for</div>' +
      '<table style="width:100%;font-size:11px"><thead><tr style="color:#7a7a7a"><th style="text-align:left">SSID</th><th>Count</th><th>Last Seen</th><th></th></tr></thead><tbody>' +
      data.probes.map(p => {
        const monitored = p.is_monitored;
        const addBtn = monitored
          ? '<span style="color:#4ade80;font-size:10px" title="Already monitored">&#x2713; GOV</span>'
          : `<button onclick="addProbeToGov('${esc(p.ssid).replace(/'/g,"\\'")}',this)" style="font-size:10px;padding:1px 6px;background:#1a3a2a;color:#4ade80;border:1px solid #2a4a3a;border-radius:3px;cursor:pointer" title="Add to Gov SSID monitoring">+ Add</button>`;
        return `<tr><td style="color:#e0e0e0">${esc(p.ssid)}</td><td style="text-align:center;color:#9a9a9a">${p.count}</td><td style="color:#7a7a7a">${ago(p.last_seen)}</td><td style="text-align:right">${addBtn}</td></tr>`;
      }).join('') +
      '</tbody></table>';
  } catch(e) {
    el.innerHTML = '<div style="padding:8px;color:#dc2626;font-size:11px">Error loading probes: ' + e.message + '</div>';
  }
}

async function addProbeToGov(ssid, btn) {
  btn.disabled = true;
  btn.textContent = '...';
  try {
    const r = await fetch('/api/gov-ssids', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ssid:ssid, label:'Discovered via LE device', category:'other', weight:50})});
    if (r.ok) {
      btn.outerHTML = '<span style="color:#4ade80;font-size:10px">&#x2713; GOV</span>';
      loadGovSSIDs();
    } else {
      btn.textContent = 'ERR';
    }
  } catch(e) {
    btn.textContent = 'ERR';
  }
}

function filterLE() {
  const q = (document.getElementById('le-search')?.value || '').toLowerCase();
  document.querySelectorAll('#le-feed tr').forEach(tr => {
    tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
  document.querySelectorAll('#le-entity-cards .health-card').forEach(card => {
    card.style.display = card.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

// --- LE Auto-Discover ---
async function discoverLE() {
  const addressInput = document.getElementById('discover-address').value.trim();
  const radius = parseInt(document.getElementById('discover-radius').value) || 10;
  const btn = document.getElementById('discover-btn');
  const status = document.getElementById('discover-status');
  const results = document.getElementById('discover-results');

  if (!addressInput) {
    toast('Enter an address, city, or zip code', true);
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Searching...';
  status.textContent = 'Geocoding and querying facilities...';
  results.innerHTML = '';

  try {
    const r = await fetch('/api/le/discover', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({address: addressInput, radius_km: radius})
    });
    const data = await r.json();

    if (!r.ok) {
      status.textContent = '';
      toast(data.error || 'Discovery failed', true);
      return;
    }

    const addrShort = data.resolved_address ? data.resolved_address.split(',').slice(0,3).join(',') + ' — ' : '';
    status.textContent = addrShort + data.facilities_found + ' facilities found, ' + data.facilities_queried + ' queried, ' + data.candidates.length + ' candidates';

    if (data.candidates.length === 0) {
      results.innerHTML = '<div style="color:#7a7a7a;font-size:11px;padding:8px 0">No LE/gov SSID candidates found in this area. Try a larger radius or different coordinates.</div>';
      return;
    }

    results.innerHTML = data.candidates.map(c => {
      const scoreColor = c.score >= 70 ? '#4ade80' : c.score >= 40 ? '#facc15' : '#9a9a9a';
      const safeSSID = esc(c.ssid).replace(/'/g, "\\'");
      const safeFType = esc(c.facility_type || 'govt').replace(/'/g, "\\'");
      const safeFacility = esc(c.facility || '').replace(/'/g, "\\'");
      return '<div class="fp-group" style="border-left:3px solid ' + scoreColor + '">' +
        '<div style="display:flex;justify-content:space-between;align-items:center">' +
          '<div>' +
            '<span style="color:#4ade80;font-weight:700">' + esc(c.ssid) + '</span>' +
            '<span style="color:#8b8b8b;font-size:10px;margin-left:8px">Score: ' + c.score + '</span>' +
          '</div>' +
          '<button onclick="addDiscoveredSSID(\'' + safeSSID + '\',\'' + safeFType + '\',\'' + safeFacility + '\',this)" style="background:#1a3a1a;border:1px solid #2d5a2d;color:#4ade80;padding:4px 10px;border-radius:3px;cursor:pointer;font-family:inherit;font-size:10px;font-weight:600">+ Add</button>' +
        '</div>' +
        '<div style="font-size:11px;color:#9a9a9a;margin-top:4px">' +
          esc(c.facility || '') + ' (' + esc(c.facility_type || '') + ')' +
          (c.channel ? ' | CH' + c.channel : '') +
          (c.encryption ? ' | ' + esc(c.encryption) : '') +
          (c.bssid ? ' | BSSID: ' + esc(c.bssid) : '') +
        '</div>' +
        '<div style="font-size:10px;color:#8b8b8b;margin-top:2px">' + (c.reasons || []).join(' &middot; ') + '</div>' +
      '</div>';
    }).join('');
  } catch (e) {
    status.textContent = '';
    toast('Discovery failed: ' + e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Discover';
  }
}

async function addDiscoveredSSID(ssid, facilityType, facilityName, btn) {
  const catMap = {police:'leo', fire_station:'fire', courthouse:'govt', government:'govt'};
  const category = catMap[facilityType] || 'govt';
  btn.disabled = true;
  btn.textContent = '...';
  try {
    const r = await fetch('/api/gov-ssids', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ssid: ssid, label: 'Discovered near ' + facilityName, category: category, weight: 50})
    });
    if (r.ok) {
      const card = btn.closest('.fp-group');
      if (card) {
        card.style.opacity = '0.4';
        card.style.pointerEvents = 'none';
      }
      btn.outerHTML = '<span style="color:#4ade80;font-size:10px;font-weight:600">Added!</span>';
      loadGovSSIDs();
    } else {
      btn.textContent = 'ERR';
      btn.disabled = false;
    }
  } catch (e) {
    btn.textContent = 'ERR';
    btn.disabled = false;
  }
}

async function testWigle() {
  const name = document.getElementById('set-wigle-name').value;
  const token = document.getElementById('set-wigle-token').value;
  if (!name || !token || name.startsWith('****') || token.startsWith('****')) {
    toast('Enter WiGLE API credentials first', true);
    return;
  }
  try {
    const r = await fetch('/api/test-wigle', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({api_name: name, api_token: token})
    });
    const d = await r.json();
    if (d.ok) toast('WiGLE connection successful!');
    else toast(d.error || 'WiGLE test failed', true);
  } catch (e) {
    toast('WiGLE test failed', true);
  }
}

function drawHealthChart(canvasId, timeline, field, label, minVal, maxVal) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !timeline || timeline.length === 0) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width = canvas.offsetWidth;
  const H = canvas.height = 250;
  const pad = {top:30, right:20, bottom:30, left:50};
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;

  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = '#0d0d0d';
  ctx.fillRect(0, 0, W, H);

  // Group by BSSID
  const series = {};
  timeline.forEach(p => {
    if (!series[p.bssid]) series[p.bssid] = [];
    series[p.bssid].push(p);
  });

  // Time range
  const times = timeline.map(p => new Date(p.timestamp.endsWith('Z') ? p.timestamp : p.timestamp + 'Z').getTime());
  const tMin = Math.min(...times);
  const tMax = Math.max(...times);
  const tRange = tMax - tMin || 1;

  // Auto-scale Y
  const allVals = timeline.map(p => p[field]).filter(v => v != null);
  if (allVals.length > 0) {
    minVal = Math.min(minVal, Math.min(...allVals) - 5);
    maxVal = Math.max(maxVal, Math.max(...allVals) + 5);
  }
  const yRange = maxVal - minVal || 1;

  // Grid lines
  ctx.strokeStyle = '#1a1a1a';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (i / 4) * plotH;
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(W - pad.right, y); ctx.stroke();
    ctx.fillStyle = '#9a9a9a';
    ctx.font = '10px monospace';
    ctx.textAlign = 'right';
    const val = maxVal - (i / 4) * yRange;
    ctx.fillText(Math.round(val).toString(), pad.left - 6, y + 4);
  }

  // Time labels
  ctx.textAlign = 'center';
  for (let i = 0; i <= 4; i++) {
    const x = pad.left + (i / 4) * plotW;
    const t = new Date(tMin + (i / 4) * tRange);
    ctx.fillStyle = '#7a7a7a';
    ctx.fillText(t.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}), x, H - 8);
  }

  // Draw series
  const colors = ['#4ade80', '#60a5fa', '#facc15', '#c084fc', '#f87171', '#fb923c'];
  let ci = 0;
  for (const [bssid, points] of Object.entries(series)) {
    const color = colors[ci % colors.length];
    ci++;
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    let started = false;
    const dotCoords = [];
    for (const p of points) {
      const val = p[field];
      if (val == null) continue;
      const t = new Date(p.timestamp.endsWith('Z') ? p.timestamp : p.timestamp + 'Z').getTime();
      const x = pad.left + ((t - tMin) / tRange) * plotW;
      const y = pad.top + ((maxVal - val) / yRange) * plotH;
      dotCoords.push({x, y, val});
      if (!started) { ctx.moveTo(x, y); started = true; }
      else ctx.lineTo(x, y);
    }
    ctx.stroke();
    // Draw dot markers at each data point (critical for sparse data visibility)
    ctx.fillStyle = color;
    for (const d of dotCoords) {
      ctx.beginPath();
      ctx.arc(d.x, d.y, 3, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  // Legend box at top-right
  const legendKeys = Object.keys(series);
  if (legendKeys.length > 0) {
    const legendX = W - pad.right - 10;
    let legendY = pad.top + 2;
    ctx.textAlign = 'right';
    ctx.font = '10px monospace';
    let lci = 0;
    for (const bssid of legendKeys) {
      const lColor = colors[lci % colors.length];
      lci++;
      ctx.fillStyle = '#0d0d0d';
      ctx.fillRect(legendX - 130, legendY - 10, 140, 14);
      ctx.fillStyle = lColor;
      ctx.fillRect(legendX - 130, legendY - 6, 8, 8);
      ctx.fillStyle = '#9a9a9a';
      ctx.fillText(bssid.substring(bssid.length - 8), legendX, legendY);
      legendY += 16;
    }
  }

  // Y-axis label
  ctx.save();
  ctx.translate(12, H / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.fillStyle = '#9a9a9a';
  ctx.font = '10px monospace';
  ctx.textAlign = 'center';
  ctx.fillText(label, 0, 0);
  ctx.restore();
}

// Show/hide label input when Mine is selected
document.getElementById('add-type').addEventListener('change', function() {
  document.getElementById('add-label').style.display = this.value === 'owned' ? '' : 'none';
});

refresh();
setInterval(refresh, 3000);

// ── Settings Drawer ──────────────────────────────────────────────────────
let settingsDirty = false;
let loadedSettings = {};

function toggleSettingsDrawer() {
  const drawer = document.getElementById('settings-drawer');
  const overlay = document.getElementById('settings-overlay');
  const isOpen = drawer.classList.contains('open');
  if (isOpen) {
    drawer.classList.remove('open');
    overlay.classList.remove('open');
  } else {
    drawer.classList.add('open');
    overlay.classList.add('open');
    loadSettings();
  }
}

async function loadSettings() {
  try {
    const r = await fetch('/api/settings');
    const d = await r.json();
    loadedSettings = d;
    // Device settings
    document.getElementById('set-device-name').value = d.device_name || '';
    document.getElementById('set-scan-interval').value = d.scan_interval || '';
    document.getElementById('set-cooldown-min').value = d.cooldown_min || '';
    // Populate WiFi interface dropdown
    await loadInterfaces(d.wifi_interface || '');
    // Alert settings
    document.getElementById('set-new-device-alerts').checked = d.new_device_alerts === '1';
    // Notification settings
    document.getElementById('set-ntfy-enabled').checked = d.ntfy_enabled === '1' || d.ntfy_enabled === undefined;
    document.getElementById('set-ntfy-topic').value = d.ntfy_topic || '';
    document.getElementById('set-ntfy-server').value = d.ntfy_server || '';
    document.getElementById('set-pushover-enabled').checked = d.pushover_enabled === '1';
    document.getElementById('set-pushover-user-key').value = d.pushover_user_key || '';
    document.getElementById('set-pushover-api-token').value = d.pushover_api_token || '';
    // WiGLE settings
    document.getElementById('set-wigle-name').value = d.wigle_api_name || '';
    document.getElementById('set-wigle-token').value = d.wigle_api_token || '';
    settingsDirty = false;
    document.getElementById('save-settings-btn').disabled = true;
  } catch (e) {
    toast('Failed to load settings', true);
  }
}

async function loadInterfaces(currentValue) {
  const sel = document.getElementById('set-wifi-interface');
  // Keep the Auto-detect option, clear the rest
  sel.innerHTML = '<option value="">Auto-detect</option>';
  try {
    const r = await fetch('/api/interfaces');
    const ifaces = await r.json();
    for (const iface of ifaces) {
      const opt = document.createElement('option');
      opt.value = iface.name;
      const mode = iface.type ? ` (${iface.type})` : '';
      opt.textContent = iface.name + mode;
      sel.appendChild(opt);
    }
  } catch (e) { /* keep just Auto-detect */ }
  sel.value = currentValue || '';
  // If the saved value isn't in the list (adapter unplugged), fall back to auto
  if (sel.value !== (currentValue || '')) sel.value = '';
}

function markSettingsDirty() {
  settingsDirty = true;
  document.getElementById('save-settings-btn').disabled = false;
}

async function saveSettings() {
  const payload = {
    device_name: document.getElementById('set-device-name').value,
    wifi_interface: document.getElementById('set-wifi-interface').value,
    scan_interval: document.getElementById('set-scan-interval').value,
    cooldown_min: document.getElementById('set-cooldown-min').value,
    new_device_alerts: document.getElementById('set-new-device-alerts').checked ? '1' : '0',
    ntfy_enabled: document.getElementById('set-ntfy-enabled').checked ? '1' : '0',
    ntfy_topic: document.getElementById('set-ntfy-topic').value,
    ntfy_server: document.getElementById('set-ntfy-server').value,
    pushover_enabled: document.getElementById('set-pushover-enabled').checked ? '1' : '0',
  };
  // Only send Pushover credentials if they don't start with **** (masked)
  const uk = document.getElementById('set-pushover-user-key').value;
  const at = document.getElementById('set-pushover-api-token').value;
  if (!uk.startsWith('****')) payload.pushover_user_key = uk;
  if (!at.startsWith('****')) payload.pushover_api_token = at;
  // WiGLE credentials (same masking logic)
  const wn = document.getElementById('set-wigle-name').value;
  const wt = document.getElementById('set-wigle-token').value;
  if (!wn.startsWith('****')) payload.wigle_api_name = wn;
  if (!wt.startsWith('****')) payload.wigle_api_token = wt;

  try {
    const r = await fetch('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const d = await r.json();
    if (d.ok) {
      toast('Settings saved');
      settingsDirty = false;
      document.getElementById('save-settings-btn').disabled = true;
      loadSettings();
    } else {
      toast(d.error || 'Save failed', true);
    }
  } catch (e) {
    toast('Save failed', true);
  }
}

async function testNotification(channel) {
  const payload = {channel};
  if (channel === 'ntfy') {
    payload.topic = document.getElementById('set-ntfy-topic').value || 'dpmb-alerts';
    payload.server = document.getElementById('set-ntfy-server').value || 'https://ntfy.sh';
  } else {
    payload.user_key = document.getElementById('set-pushover-user-key').value;
    payload.api_token = document.getElementById('set-pushover-api-token').value;
    if (!payload.user_key || !payload.api_token || payload.user_key.startsWith('****') || payload.api_token.startsWith('****')) {
      toast('Enter Pushover credentials first', true); return;
    }
  }
  try {
    const r = await fetch('/api/test-notification', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const d = await r.json();
    if (d.ok) toast('Test notification sent!');
    else toast(d.error || 'Test failed', true);
  } catch (e) {
    toast('Test failed', true);
  }
}

// ── Guided Tour ──────────────────────────────────────────────────────────
const tourSteps = [
  { target: '.hdr', title: 'Welcome to 802.11DPMB', desc: 'Don\'t Probe Me Bro — a real-time 802.11 probe request monitor and wireless intrusion detection system. Let\'s take a quick tour!' },
  { target: '.stats', title: 'Stats Bar', desc: 'Live counters showing total probes, watchlist matches, LE detections, security events, active devices, and known APs.' },
  { target: '.tabs', title: 'Navigation Tabs', desc: 'Switch between dashboard views: Health, Live feed, WIDS alerts, Watchlist, Devices, Timeline, Neighbors, and LE Activity.' },
  { target: '.wl-bar', title: 'Watchlist', desc: 'Add SSIDs to watch for (alert) or mark as yours (owned). Type an SSID, select Watch or Mine, and click Add.' },
  { target: '#p-health', title: 'Health Tab', desc: 'Monitor your owned AP signal strength, channel congestion, and network health events in real time.' },
  { target: '[onclick="switchTab(\'live\')"]', title: 'Live Feed', desc: 'Real-time stream of all probe requests captured by the scanner. Watchlist matches highlighted in red, LE in blue.' },
  { target: '[onclick="switchTab(\'wids\')"]', title: 'WIDS Alerts', desc: 'Wireless Intrusion Detection — evil twins, karma attacks, deauth floods, encryption downgrades, and more.' },
  { target: '[onclick="switchTab(\'devices\')"]', title: 'Devices', desc: 'All devices seen probing nearby. Label them, mark as known, and track their SSID fingerprints.' },
  { target: '.gear-btn', title: 'Settings', desc: 'Configure your device (name, interface, scan interval) and push notifications (ntfy.sh, Pushover). Click the gear icon anytime.' },
];
let tourCurrent = 0;

function startTour() {
  if (localStorage.getItem('dpmb_tour_completed')) return;
  tourCurrent = 0;
  document.getElementById('tour-overlay').classList.add('active');
  showTourStep();
}

function showTourStep() {
  if (tourCurrent >= tourSteps.length) { endTour(); return; }
  const step = tourSteps[tourCurrent];
  const el = document.querySelector(step.target);
  const highlight = document.getElementById('tour-highlight');
  const tooltip = document.getElementById('tour-tooltip');

  document.getElementById('tour-step').textContent = 'Step ' + (tourCurrent + 1) + ' of ' + tourSteps.length;
  document.getElementById('tour-title').textContent = step.title;
  document.getElementById('tour-desc').textContent = step.desc;

  // Update button text for last step
  const nextBtn = tooltip.querySelector('.tour-next');
  nextBtn.textContent = tourCurrent === tourSteps.length - 1 ? 'Finish' : 'Next';

  if (el) {
    const rect = el.getBoundingClientRect();
    highlight.style.left = (rect.left - 4) + 'px';
    highlight.style.top = (rect.top - 4) + 'px';
    highlight.style.width = (rect.width + 8) + 'px';
    highlight.style.height = (rect.height + 8) + 'px';
    highlight.style.display = 'block';

    // Position tooltip below target
    let tTop = rect.bottom + 12;
    let tLeft = rect.left;
    if (tTop + 200 > window.innerHeight) tTop = rect.top - 180;
    if (tLeft + 320 > window.innerWidth) tLeft = window.innerWidth - 340;
    if (tLeft < 10) tLeft = 10;
    tooltip.style.top = tTop + 'px';
    tooltip.style.left = tLeft + 'px';
  } else {
    highlight.style.display = 'none';
    tooltip.style.top = '50%';
    tooltip.style.left = '50%';
    tooltip.style.transform = 'translate(-50%, -50%)';
  }
}

function nextTourStep() {
  tourCurrent++;
  if (tourCurrent >= tourSteps.length) { endTour(); return; }
  showTourStep();
}

function endTour() {
  document.getElementById('tour-overlay').classList.remove('active');
  localStorage.setItem('dpmb_tour_completed', '1');
}

// Start tour after initial data load
setTimeout(startTour, 1500);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _get_ro_db():
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _get_rw_db():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/feed")
def api_feed():
    db = _get_ro_db()
    try:
        # Watchlist
        watchlist_rows = db.execute(
            "SELECT ssid, watch_type, label FROM watchlist WHERE active = 1"
        ).fetchall()
        watched_alert = {r["ssid"] for r in watchlist_rows if r["watch_type"] == "alert"}
        watched_owned = {}
        for r in watchlist_rows:
            if r["watch_type"] == "owned":
                watched_owned[r["ssid"]] = r["label"] or ""
        watched = watched_alert | set(watched_owned.keys())

        # Recent probes (last 300)
        probes = db.execute(
            "SELECT ssid, device_mac, rssi, channel, seen_at, matched "
            "FROM probe_log ORDER BY seen_at DESC LIMIT 300"
        ).fetchall()

        classified = []
        for p in probes:
            ssid, mac = p["ssid"], p["device_mac"]
            if ssid in watched_owned:
                tag, detail = "mine", watched_owned[ssid]
            elif ssid in watched_alert or p["matched"]:
                tag, detail = "match", ""
            else:
                tag, detail = classify_probe(ssid, mac)
            classified.append({
                "ssid": ssid, "device_mac": mac, "rssi": p["rssi"],
                "channel": p["channel"], "seen_at": p["seen_at"],
                "tag": tag, "detail": detail,
                "vendor": lookup_vendor(mac),
            })

        # Stats (5 min)
        stats = db.execute("""
            SELECT COUNT(*) as total, COUNT(DISTINCT device_mac) as devices,
                   COUNT(DISTINCT ssid) as ssids, SUM(matched) as matches
            FROM probe_log WHERE seen_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-5 minutes')
        """).fetchone()

        # LE hits (5 min) — from persistent le_detections table
        le_count = 0
        try:
            le_row = db.execute(
                "SELECT COUNT(*) as cnt FROM le_detections "
                "WHERE seen_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-5 minutes')"
            ).fetchone()
            le_count = le_row["cnt"] if le_row else 0
        except Exception:
            # Fallback to display-time classification if table doesn't exist
            recent = db.execute(
                "SELECT ssid, device_mac FROM probe_log "
                "WHERE seen_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-5 minutes')"
            ).fetchall()
            for r in recent:
                t, _ = classify_probe(r["ssid"], r["device_mac"])
                if t == "le":
                    le_count += 1

        # Total unique devices
        total_devices = 0
        try:
            td_row = db.execute("SELECT COUNT(*) as cnt FROM devices").fetchone()
            total_devices = td_row["cnt"] if td_row else 0
        except Exception:
            pass

        # Randomized MAC count (devices seen in last 5 minutes)
        randomized_5m = 0
        try:
            rand_row = db.execute(
                "SELECT COUNT(DISTINCT d.mac) as cnt FROM devices d "
                "INNER JOIN probe_log p ON d.mac = p.device_mac "
                "WHERE d.is_randomized = 1 "
                "AND p.seen_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-5 minutes')"
            ).fetchone()
            randomized_5m = rand_row["cnt"] if rand_row else 0
        except Exception:
            pass

        return jsonify({
            "probes": classified,
            "total_probes_5m": stats["total"] or 0,
            "unique_devices_5m": stats["devices"] or 0,
            "unique_ssids_5m": stats["ssids"] or 0,
            "matches_5m": stats["matches"] or 0,
            "le_hits_5m": le_count,
            "total_devices": total_devices,
            "randomized_5m": randomized_5m,
            "watchlist": [{"ssid": r["ssid"], "watch_type": r["watch_type"] or "alert", "label": r["label"]} for r in watchlist_rows],
        })
    finally:
        db.close()


@app.route("/api/devices")
def api_devices():
    db = _get_ro_db()
    try:
        # Watchlist for highlighting
        watched = {r["ssid"] for r in db.execute("SELECT ssid FROM watchlist WHERE active = 1").fetchall()}

        # All devices, most recently seen first
        rows = db.execute(
            "SELECT mac, first_seen, last_seen, probe_count, label, is_known, "
            "avg_rssi, min_rssi, max_rssi, is_randomized FROM devices ORDER BY last_seen DESC LIMIT 200"
        ).fetchall()

        devices = []
        for d in rows:
            mac = d["mac"]
            # Get SSID fingerprint
            ssid_rows = db.execute(
                "SELECT ssid, count FROM device_ssids WHERE device_mac = ? ORDER BY count DESC LIMIT 20",
                (mac,),
            ).fetchall()
            ssids = [s["ssid"] for s in ssid_rows]

            # OUI vendor (full database)
            vendor = lookup_vendor(mac)

            # Check if "new" (first seen in last 10 minutes)
            is_new = False
            try:
                import datetime
                fs = d["first_seen"]
                if fs:
                    from datetime import datetime as dt, timezone, timedelta
                    first = dt.fromisoformat(fs.replace("Z", "+00:00"))
                    is_new = (dt.now(timezone.utc) - first).total_seconds() < 600
            except Exception:
                pass

            devices.append({
                "mac": mac,
                "first_seen": d["first_seen"],
                "last_seen": d["last_seen"],
                "probe_count": d["probe_count"],
                "label": d["label"],
                "is_known": bool(d["is_known"]),
                "avg_rssi": round(d["avg_rssi"]) if d["avg_rssi"] else None,
                "min_rssi": d["min_rssi"],
                "max_rssi": d["max_rssi"],
                "ssids": ssids,
                "vendor": vendor,
                "is_new": is_new,
                "is_randomized": bool(d["is_randomized"]),
            })

        return jsonify({"devices": devices})
    finally:
        db.close()


@app.route("/api/timeline")
def api_timeline():
    db = _get_ro_db()
    try:
        rows = db.execute(
            "SELECT p.device_mac, p.event_type, p.timestamp, p.rssi, p.ssid, "
            "d.label FROM presence_log p "
            "LEFT JOIN devices d ON p.device_mac = d.mac "
            "ORDER BY p.timestamp DESC LIMIT 200"
        ).fetchall()

        events = []
        for r in rows:
            # Calculate dwell time for depart events
            dwell_sec = None
            if r["event_type"] == "depart":
                arrive = db.execute(
                    "SELECT timestamp FROM presence_log "
                    "WHERE device_mac = ? AND event_type = 'arrive' AND timestamp < ? "
                    "ORDER BY timestamp DESC LIMIT 1",
                    (r["device_mac"], r["timestamp"]),
                ).fetchone()
                if arrive:
                    try:
                        from datetime import datetime as dt
                        a = dt.fromisoformat(arrive["timestamp"].replace("Z", "+00:00"))
                        dep = dt.fromisoformat(r["timestamp"].replace("Z", "+00:00"))
                        dwell_sec = int((dep - a).total_seconds())
                    except Exception:
                        pass

            events.append({
                "device_mac": r["device_mac"],
                "event_type": r["event_type"],
                "timestamp": r["timestamp"],
                "rssi": r["rssi"],
                "ssid": r["ssid"],
                "label": r["label"],
                "dwell_sec": dwell_sec,
            })

        return jsonify({"events": events})
    finally:
        db.close()


@app.route("/api/neighbors")
def api_neighbors():
    db = _get_ro_db()
    try:
        # Get owned SSIDs and their channels
        owned_rows = db.execute(
            "SELECT ssid FROM watchlist WHERE active = 1 AND watch_type = 'owned'"
        ).fetchall()
        owned_ssids = {r["ssid"] for r in owned_rows}

        # Get owned AP channels
        owned_channels = set()
        if owned_ssids:
            placeholders = ",".join("?" * len(owned_ssids))
            ch_rows = db.execute(
                f"SELECT DISTINCT channel FROM access_points WHERE ssid IN ({placeholders}) AND is_trusted = 1",
                list(owned_ssids),
            ).fetchall()
            owned_channels = {r["channel"] for r in ch_rows if r["channel"]}

        # Get all non-owned APs
        rows = db.execute(
            "SELECT bssid, ssid, channel, encryption, first_seen, last_seen, "
            "beacon_count, avg_rssi, min_rssi, max_rssi, is_trusted, label "
            "FROM access_points WHERE is_trusted = 0 ORDER BY last_seen DESC LIMIT 200"
        ).fetchall()

        neighbors = []
        for r in rows:
            bssid = r["bssid"]
            ssid = r["ssid"]
            channel = r["channel"]

            # LE classification
            is_le = False
            le_detail = ""
            if ssid:
                tag, detail = classify_probe(ssid, bssid)
                if tag == "le":
                    is_le = True
                    le_detail = detail

            # OUI vendor
            vendor = lookup_vendor(bssid)

            # Check if new (first seen in last 24h)
            is_new = False
            try:
                from datetime import datetime as dt, timezone, timedelta
                if r["first_seen"]:
                    first = dt.fromisoformat(r["first_seen"].replace("Z", "+00:00"))
                    is_new = (dt.now(timezone.utc) - first).total_seconds() < 86400
            except Exception:
                pass

            # RSSI history (last 2h from ap_history)
            rssi_history = []
            try:
                hist_rows = db.execute(
                    "SELECT rssi, seen_at FROM ap_history "
                    "WHERE bssid = ? AND seen_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-2 hours') "
                    "ORDER BY seen_at ASC LIMIT 30",
                    (bssid,),
                ).fetchall()
                rssi_history = [{"rssi": h["rssi"], "t": h["seen_at"]} for h in hist_rows if h["rssi"]]
            except Exception:
                pass

            neighbors.append({
                "bssid": bssid,
                "ssid": ssid,
                "channel": channel,
                "encryption": r["encryption"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "beacon_count": r["beacon_count"],
                "avg_rssi": r["avg_rssi"],
                "same_channel": channel in owned_channels,
                "is_le": is_le,
                "le_detail": le_detail,
                "is_new": is_new,
                "vendor": vendor,
                "rssi_history": rssi_history,
            })

        return jsonify({"neighbors": neighbors})
    finally:
        db.close()


# ---------------------------------------------------------------------------
# RSSI history (for sparklines)
# ---------------------------------------------------------------------------

@app.route("/api/device/<path:mac>/rssi_history")
def api_rssi_history(mac):
    db = _get_ro_db()
    try:
        rows = db.execute(
            "SELECT rssi, seen_at FROM probe_log WHERE device_mac = ? "
            "ORDER BY seen_at DESC LIMIT 50",
            (mac,),
        ).fetchall()
        # Return oldest-first for sparkline rendering
        points = [{"rssi": r["rssi"], "t": r["seen_at"]} for r in reversed(rows)]
        return jsonify({"mac": mac, "points": points})
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Fingerprint groups (SSID-based device clustering to defeat MAC randomization)
# ---------------------------------------------------------------------------

@app.route("/api/fingerprint_groups")
def api_fingerprint_groups():
    db = _get_ro_db()
    try:
        # Get all device SSID sets
        rows = db.execute(
            "SELECT device_mac, GROUP_CONCAT(ssid) as ssids "
            "FROM device_ssids GROUP BY device_mac HAVING COUNT(ssid) >= 2"
        ).fetchall()

        # Build SSID sets per device
        device_ssids = {}
        for r in rows:
            mac = r["device_mac"]
            ssids = set(r["ssids"].split(","))
            device_ssids[mac] = ssids

        # Get labels
        labels = {}
        for d in db.execute("SELECT mac, label FROM devices WHERE label IS NOT NULL").fetchall():
            labels[d["mac"]] = d["label"]

        # Jaccard similarity clustering
        macs = list(device_ssids.keys())
        groups = []
        used = set()

        for i, mac_a in enumerate(macs):
            if mac_a in used:
                continue
            group = [mac_a]
            used.add(mac_a)
            set_a = device_ssids[mac_a]

            for mac_b in macs[i + 1:]:
                if mac_b in used:
                    continue
                set_b = device_ssids[mac_b]
                intersection = len(set_a & set_b)
                union = len(set_a | set_b)
                if union > 0 and intersection / union >= 0.5:
                    group.append(mac_b)
                    used.add(mac_b)

            if len(group) >= 2:
                shared = set_a.copy()
                for m in group[1:]:
                    shared &= device_ssids[m]
                groups.append({
                    "devices": [{"mac": m, "label": labels.get(m), "vendor": lookup_vendor(m)} for m in group],
                    "shared_ssids": sorted(shared),
                    "similarity": round(len(shared) / max(len(set_a), 1), 2),
                })

        return jsonify({"groups": groups})
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Watchlist + Device management endpoints
# ---------------------------------------------------------------------------

@app.route("/api/watchlist/detail")
def api_watchlist_detail():
    db = _get_ro_db()
    try:
        rows = db.execute(
            "SELECT ssid, watch_type, label FROM watchlist WHERE active = 1 ORDER BY watch_type, ssid"
        ).fetchall()

        entries = []
        alert_hits = 0

        for r in rows:
            ssid = r["ssid"]
            wt = r["watch_type"]

            entry = {
                "ssid": ssid,
                "watch_type": wt,
                "label": r["label"],
            }

            if wt == "alert":
                stats = db.execute(
                    "SELECT COUNT(*) as total, COUNT(DISTINCT device_mac) as devices, "
                    "MAX(seen_at) as last_seen "
                    "FROM probe_log WHERE ssid = ?",
                    (ssid,),
                ).fetchone()
                entry["total_probes"] = stats["total"] or 0
                entry["unique_devices"] = stats["devices"] or 0
                entry["last_seen"] = stats["last_seen"]

                if stats["total"]:
                    alert_hits += stats["total"]

                recent = db.execute(
                    "SELECT device_mac, rssi, channel, seen_at "
                    "FROM probe_log WHERE ssid = ? "
                    "ORDER BY seen_at DESC LIMIT 20",
                    (ssid,),
                ).fetchall()
                entry["recent_probes"] = [{
                    "device_mac": p["device_mac"],
                    "rssi": p["rssi"],
                    "channel": p["channel"],
                    "seen_at": p["seen_at"],
                    "vendor": lookup_vendor(p["device_mac"]),
                } for p in recent]

            elif wt == "owned":
                aps = db.execute(
                    "SELECT bssid, channel, avg_rssi, last_seen "
                    "FROM access_points WHERE ssid = ? AND is_trusted = 1 "
                    "ORDER BY last_seen DESC",
                    (ssid,),
                ).fetchall()
                entry["ap_count"] = len(aps)
                entry["aps"] = [{
                    "bssid": a["bssid"],
                    "channel": a["channel"],
                    "rssi": round(a["avg_rssi"]) if a["avg_rssi"] else None,
                    "last_seen": a["last_seen"],
                } for a in aps]

            entries.append(entry)

        return jsonify({"entries": entries, "alert_hits": alert_hits})
    finally:
        db.close()


@app.route("/api/watchlist", methods=["POST"])
def api_watchlist_add():
    data = request.get_json(force=True)
    ssid = (data.get("ssid") or "").strip()
    if not ssid:
        return jsonify({"ok": False, "error": "SSID required"}), 400
    if len(ssid.encode("utf-8")) > 32:
        return jsonify({"ok": False, "error": "SSID exceeds 32-byte limit"}), 400

    watch_type = data.get("watch_type", "alert")
    if watch_type not in ("alert", "owned"):
        watch_type = "alert"
    label = (data.get("label") or "").strip() or None

    db = _get_rw_db()
    try:
        existing = db.execute("SELECT id FROM watchlist WHERE ssid = ?", (ssid,)).fetchone()
        if existing:
            db.execute(
                "UPDATE watchlist SET watch_type = ?, label = ?, active = 1 WHERE ssid = ?",
                (watch_type, label, ssid),
            )
        else:
            db.execute(
                "INSERT INTO watchlist (ssid, watch_type, label) VALUES (?, ?, ?)",
                (ssid, watch_type, label),
            )
        # Auto-trust APs broadcasting this owned SSID
        if watch_type == "owned":
            db.execute(
                "UPDATE access_points SET is_trusted = 1 WHERE ssid = ?", (ssid,)
            )
        db.commit()
        return jsonify({"ok": True, "ssid": ssid})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/watchlist", methods=["DELETE"])
def api_watchlist_remove():
    data = request.get_json(force=True)
    ssid = (data.get("ssid") or "").strip()
    if not ssid:
        return jsonify({"ok": False, "error": "SSID required"}), 400

    db = _get_rw_db()
    try:
        db.execute("DELETE FROM watchlist WHERE ssid = ?", (ssid,))
        db.commit()
        return jsonify({"ok": True, "ssid": ssid})
    finally:
        db.close()


@app.route("/api/device/<path:mac>/label", methods=["POST"])
def api_device_label(mac):
    data = request.get_json(force=True)
    label = (data.get("label") or "").strip()

    db = _get_rw_db()
    try:
        db.execute("UPDATE devices SET label = ? WHERE mac = ?", (label or None, mac))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/device/<path:mac>/known", methods=["POST"])
def api_device_known(mac):
    data = request.get_json(force=True)
    known = 1 if data.get("known") else 0

    db = _get_rw_db()
    try:
        db.execute("UPDATE devices SET is_known = ? WHERE mac = ?", (known, mac))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        db.close()


# ---------------------------------------------------------------------------
# WIDS endpoints — AP inventory, alerts, trust management
# ---------------------------------------------------------------------------

@app.route("/api/access_points")
def api_access_points():
    db = _get_ro_db()
    try:
        rows = db.execute(
            "SELECT bssid, ssid, channel, encryption, first_seen, last_seen, "
            "beacon_count, avg_rssi, min_rssi, max_rssi, is_trusted, label "
            "FROM access_points ORDER BY last_seen DESC LIMIT 200"
        ).fetchall()
        aps = [{
            "bssid": r["bssid"], "ssid": r["ssid"], "channel": r["channel"],
            "encryption": r["encryption"], "first_seen": r["first_seen"],
            "last_seen": r["last_seen"], "beacon_count": r["beacon_count"],
            "avg_rssi": r["avg_rssi"], "min_rssi": r["min_rssi"],
            "max_rssi": r["max_rssi"], "is_trusted": bool(r["is_trusted"]),
            "label": r["label"],
        } for r in rows]
        return jsonify({"access_points": aps})
    finally:
        db.close()


@app.route("/api/wids_alerts")
def api_wids_alerts():
    db = _get_ro_db()
    try:
        rows = db.execute(
            "SELECT id, alert_type, severity, bssid, device_mac, ssid, detail, "
            "seen_at, acknowledged FROM wids_alerts ORDER BY seen_at DESC LIMIT 200"
        ).fetchall()
        unack = db.execute(
            "SELECT COUNT(*) as cnt FROM wids_alerts WHERE acknowledged = 0"
        ).fetchone()
        alerts = [{
            "id": r["id"], "alert_type": r["alert_type"], "severity": r["severity"],
            "bssid": r["bssid"], "device_mac": r["device_mac"], "ssid": r["ssid"],
            "detail": r["detail"], "seen_at": r["seen_at"],
            "acknowledged": bool(r["acknowledged"]),
        } for r in rows]
        return jsonify({"alerts": alerts, "unacknowledged": unack["cnt"] if unack else 0})
    finally:
        db.close()


@app.route("/api/wids_alerts/<int:alert_id>/acknowledge", methods=["POST"])
def api_wids_alert_ack(alert_id):
    db = _get_rw_db()
    try:
        db.execute("UPDATE wids_alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/access_points/<path:bssid>/trust", methods=["POST"])
def api_ap_trust(bssid):
    data = request.get_json(force=True)
    trusted = 1 if data.get("trusted") else 0
    db = _get_rw_db()
    try:
        db.execute("UPDATE access_points SET is_trusted = ? WHERE bssid = ?", (trusted, bssid))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/health/summary")
def api_health_summary():
    db = _get_ro_db()
    try:
        # Get owned BSSIDs with latest health snapshot
        owned_rows = db.execute(
            "SELECT ssid FROM watchlist WHERE active = 1 AND watch_type = 'owned'"
        ).fetchall()
        owned_ssids = {r["ssid"] for r in owned_rows}

        nodes = []
        if owned_ssids:
            placeholders = ",".join("?" * len(owned_ssids))
            # Source BSSIDs from network_health (reliable) — access_points.ssid
            # can be empty for hidden-SSID APs even when health snapshots record
            # the correct SSID from the watchlist.
            bssid_rows = db.execute(
                f"SELECT DISTINCT bssid, ssid FROM network_health WHERE ssid IN ({placeholders})",
                list(owned_ssids),
            ).fetchall()

            for br in bssid_rows:
                # Latest snapshot
                latest = db.execute(
                    "SELECT rssi, channel, channel_ap_count, channel_client_count, "
                    "noise_floor_est, snr_est, timestamp "
                    "FROM network_health WHERE bssid = ? ORDER BY timestamp DESC LIMIT 1",
                    (br["bssid"],),
                ).fetchone()

                # RSSI history — adaptive window (2h → 24h → 7d → all)
                history = []
                for window in ('-2 hours', '-24 hours', '-7 days', None):
                    if window:
                        history = db.execute(
                            "SELECT rssi, timestamp FROM network_health "
                            "WHERE bssid = ? AND timestamp >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '" + window + "') "
                            "ORDER BY timestamp ASC",
                            (br["bssid"],),
                        ).fetchall()
                    else:
                        history = db.execute(
                            "SELECT rssi, timestamp FROM network_health "
                            "WHERE bssid = ? ORDER BY timestamp ASC",
                            (br["bssid"],),
                        ).fetchall()
                    if history:
                        break
                rssi_history = [{"rssi": h["rssi"], "t": h["timestamp"]} for h in history]

                nodes.append({
                    "bssid": br["bssid"],
                    "ssid": br["ssid"],
                    "rssi": latest["rssi"] if latest else None,
                    "channel": latest["channel"] if latest else None,
                    "channel_ap_count": latest["channel_ap_count"] if latest else 0,
                    "channel_client_count": latest["channel_client_count"] if latest else 0,
                    "snr_est": latest["snr_est"] if latest else None,
                    "rssi_history": rssi_history,
                    "last_update": latest["timestamp"] if latest else None,
                })

        # Timeline data (all owned BSSIDs — adaptive window)
        # Query network_health directly by SSID (not via access_points JOIN
        # which can miss hidden-SSID APs with empty access_points.ssid).
        timeline = []
        if owned_ssids:
            placeholders = ",".join("?" * len(owned_ssids))
            for window in ('-2 hours', '-24 hours', '-7 days', None):
                if window:
                    tl_rows = db.execute(
                        f"SELECT bssid, ssid, rssi, channel, channel_ap_count, "
                        f"channel_client_count, noise_floor_est, snr_est, timestamp "
                        f"FROM network_health "
                        f"WHERE ssid IN ({placeholders}) "
                        f"AND timestamp >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '{window}') "
                        f"ORDER BY timestamp ASC",
                        list(owned_ssids),
                    ).fetchall()
                else:
                    tl_rows = db.execute(
                        f"SELECT bssid, ssid, rssi, channel, channel_ap_count, "
                        f"channel_client_count, noise_floor_est, snr_est, timestamp "
                        f"FROM network_health "
                        f"WHERE ssid IN ({placeholders}) "
                        f"ORDER BY timestamp ASC",
                        list(owned_ssids),
                    ).fetchall()
                if tl_rows:
                    break
            timeline = [{
                "bssid": r["bssid"], "ssid": r["ssid"], "rssi": r["rssi"],
                "channel": r["channel"], "channel_ap_count": r["channel_ap_count"],
                "channel_client_count": r["channel_client_count"],
                "noise_floor_est": r["noise_floor_est"], "snr_est": r["snr_est"],
                "timestamp": r["timestamp"],
            } for r in tl_rows]

        # Health-related WIDS alerts
        health_types = ('signal_degradation', 'channel_congestion', 'beacon_loss')
        placeholders_ht = ",".join("?" * len(health_types))
        health_events = db.execute(
            f"SELECT alert_type, severity, bssid, ssid, detail, seen_at "
            f"FROM wids_alerts WHERE alert_type IN ({placeholders_ht}) "
            f"ORDER BY seen_at DESC LIMIT 50",
            health_types,
        ).fetchall()
        events = [{
            "alert_type": e["alert_type"], "severity": e["severity"],
            "bssid": e["bssid"], "ssid": e["ssid"],
            "detail": e["detail"], "seen_at": e["seen_at"],
        } for e in health_events]

        # Network environment: channel distribution + summary stats
        channel_dist = db.execute(
            "SELECT channel, COUNT(*) as ap_count, "
            "ROUND(AVG(avg_rssi), 1) as avg_rssi "
            "FROM access_points WHERE channel IS NOT NULL "
            "GROUP BY channel ORDER BY channel"
        ).fetchall()
        env_channels = [{
            "channel": r["channel"], "ap_count": r["ap_count"],
            "avg_rssi": r["avg_rssi"],
        } for r in channel_dist]

        total_aps = sum(r["ap_count"] for r in channel_dist)
        total_devices_row = db.execute("SELECT COUNT(*) as c FROM devices").fetchone()
        total_devices = total_devices_row["c"] if total_devices_row else 0
        probes_1h = db.execute(
            "SELECT COUNT(*) as c FROM probe_log "
            "WHERE seen_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hour')"
        ).fetchone()
        probe_count_1h = probes_1h["c"] if probes_1h else 0

        return jsonify({
            "nodes": nodes,
            "timeline": timeline,
            "health_events": events,
            "environment": {
                "channels": env_channels,
                "total_aps": total_aps,
                "total_devices": total_devices,
                "probes_1h": probe_count_1h,
            },
        })
    finally:
        db.close()


@app.route("/api/le/activity")
def api_le_activity():
    """Return LE detection events with entities, trajectories, and stats."""
    db = _get_ro_db()
    try:
        # Recent detections (last 24h)
        rows = db.execute(
            "SELECT id, mac, ssid, confidence, detail, factors, rssi, channel, "
            "source_type, trend, seen_at FROM le_detections "
            "WHERE seen_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-24 hours') "
            "ORDER BY seen_at DESC LIMIT 200"
        ).fetchall()

        detections = [{
            "id": r["id"], "mac": r["mac"], "ssid": r["ssid"],
            "confidence": r["confidence"], "detail": r["detail"],
            "factors": r["factors"].split(",") if r["factors"] else [],
            "rssi": r["rssi"], "channel": r["channel"],
            "source_type": r["source_type"], "trend": r["trend"],
            "seen_at": r["seen_at"],
        } for r in rows]

        # Unique entities grouped by MAC
        entity_rows = db.execute(
            "SELECT mac, MAX(confidence) as max_confidence, COUNT(*) as cnt, "
            "MAX(seen_at) as last_seen, MIN(seen_at) as first_seen, "
            "GROUP_CONCAT(DISTINCT ssid) as ssids, AVG(rssi) as avg_rssi "
            "FROM le_detections "
            "WHERE seen_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-24 hours') "
            "GROUP BY mac ORDER BY last_seen DESC"
        ).fetchall()

        entities = [{
            "mac": r["mac"],
            "max_confidence": r["max_confidence"],
            "detection_count": r["cnt"],
            "last_seen": r["last_seen"],
            "first_seen": r["first_seen"],
            "ssids": list(set(r["ssids"].split(",") if r["ssids"] else [])),
            "avg_rssi": round(r["avg_rssi"]) if r["avg_rssi"] else None,
        } for r in entity_rows]

        # Signal trajectory per entity
        trajectories = {}
        for entity in entities:
            mac = entity["mac"]
            traj_rows = db.execute(
                "SELECT rssi, seen_at FROM le_detections "
                "WHERE mac = ? AND seen_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-24 hours') "
                "ORDER BY seen_at ASC",
                (mac,),
            ).fetchall()
            trajectories[mac] = [{"rssi": t["rssi"], "t": t["seen_at"]} for t in traj_rows]

        # Stats
        stats = db.execute(
            "SELECT COUNT(*) as total, COUNT(DISTINCT mac) as unique_macs "
            "FROM le_detections "
            "WHERE seen_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-24 hours')"
        ).fetchone()

        return jsonify({
            "detections": detections,
            "entities": entities,
            "trajectories": trajectories,
            "stats": {
                "total_24h": stats["total"] if stats else 0,
                "unique_entities_24h": stats["unique_macs"] if stats else 0,
            },
        })
    finally:
        db.close()


# ---------------------------------------------------------------------------
# LE SSID Auto-Discovery endpoint
# ---------------------------------------------------------------------------

@app.route("/api/le/discover", methods=["POST"])
def api_le_discover():
    """Discover LE/gov SSIDs using Overpass + WiGLE APIs."""
    data = request.get_json(force=True)
    address = data.get("address", "").strip()
    lat = data.get("lat")
    lon = data.get("lon")
    radius_km = data.get("radius_km", 10)

    # Geocode address server-side (Census first for US, Nominatim fallback)
    resolved_address = ""
    if address and (lat is None or lon is None):
        # Try US Census geocoder first (handles US addresses, streets, zip codes)
        try:
            census_resp = http_requests.get(
                "https://geocoding.geo.census.gov/geocoder/locations/onelineaddress",
                params={
                    "address": address,
                    "benchmark": "Public_AR_Current",
                    "format": "json",
                },
                timeout=10,
            )
            census_resp.raise_for_status()
            matches = census_resp.json().get("result", {}).get("addressMatches", [])
            if matches:
                coords = matches[0].get("coordinates", {})
                lat = float(coords["y"])
                lon = float(coords["x"])
                resolved_address = matches[0].get("matchedAddress", address)
        except Exception:
            pass

        # Fallback: Nominatim (international, city names, landmarks)
        if lat is None or lon is None:
            try:
                geo_resp = http_requests.get(
                    "https://nominatim.openstreetmap.org/search",
                    params={"format": "json", "limit": 1, "countrycodes": "us", "q": address},
                    headers={"User-Agent": "DPMB-Dashboard/0.3.0"},
                    timeout=10,
                )
                geo_resp.raise_for_status()
                geo_data = geo_resp.json()
                if geo_data:
                    lat = float(geo_data[0]["lat"])
                    lon = float(geo_data[0]["lon"])
                    resolved_address = geo_data[0].get("display_name", "")
            except Exception:
                pass

        if lat is None or lon is None:
            return jsonify({"ok": False, "error": f"Could not find location: {address}"}), 400

    try:
        lat = float(lat)
        lon = float(lon)
        radius_km = float(radius_km)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "Invalid coordinates"}), 400

    # Read WiGLE credentials from settings
    db = _get_ro_db()
    try:
        api_name = get_setting(db, "wigle_api_name", "")
        api_token = get_setting(db, "wigle_api_token", "")
    finally:
        db.close()

    if not api_name or not api_token:
        return jsonify({"ok": False, "error": "WiGLE credentials not configured. Add them in Settings."}), 400

    # Step 1: Query Overpass for facilities
    facilities = _query_overpass(lat, lon, radius_km)
    facilities_found = len(facilities)

    # Step 2: Limit to closest 15 facilities if needed
    if len(facilities) > 15:
        # Sort by distance from center
        for f in facilities:
            f["_dist"] = math.sqrt((f["lat"] - lat) ** 2 + (f["lon"] - lon) ** 2)
        facilities.sort(key=lambda f: f["_dist"])
        facilities = facilities[:15]

    facilities_queried = len(facilities)

    # Step 3: Query WiGLE for each facility
    all_candidates = {}  # ssid -> best candidate info
    for i, facility in enumerate(facilities):
        if i > 0:
            time.sleep(1)  # Rate limit: 1 second between queries

        ssids = _query_wigle_facility(
            facility["lat"], facility["lon"], api_name, api_token
        )

        for net in ssids:
            ssid = net["ssid"]
            key = ssid.lower()

            if key in all_candidates:
                all_candidates[key]["facility_count"] += 1
                # Keep the highest-scoring facility association
            else:
                all_candidates[key] = {
                    "ssid": ssid,
                    "bssid": net.get("bssid", ""),
                    "encryption": net.get("encryption", ""),
                    "last_seen": net.get("last_seen", ""),
                    "channel": net.get("channel", 0),
                    "facility": facility["name"],
                    "facility_type": facility["type"],
                    "facility_count": 1,
                }

    # Step 4: Score and filter candidates (exclude already-added SSIDs)
    try:
        existing_ssids = {
            r["ssid"] for r in db.execute("SELECT ssid FROM watchlist WHERE active = 1").fetchall()
        }
    except Exception:
        existing_ssids = set()

    results = []
    for key, c in all_candidates.items():
        if c["ssid"] in existing_ssids:
            continue
        score, reasons = _score_ssid_candidate(c, c["facility_count"])
        if score >= 20:
            results.append({
                "ssid": c["ssid"],
                "bssid": c["bssid"],
                "score": score,
                "reasons": reasons,
                "facility": c["facility"],
                "facility_type": c["facility_type"],
                "encryption": c["encryption"],
                "last_seen": c["last_seen"],
                "channel": c["channel"],
            })

    # Sort by score descending
    results.sort(key=lambda r: r["score"], reverse=True)

    return jsonify({
        "facilities_found": facilities_found,
        "facilities_queried": facilities_queried,
        "candidates": results,
        "resolved_address": resolved_address,
    })


@app.route("/api/test-wigle", methods=["POST"])
def api_test_wigle():
    """Test WiGLE API credentials by hitting the profile endpoint."""
    data = request.get_json(force=True)
    api_name = (data.get("api_name") or "").strip()
    api_token = (data.get("api_token") or "").strip()

    if not api_name or not api_token:
        return jsonify({"ok": False, "error": "API name and token required"}), 400

    try:
        resp = http_requests.get(
            "https://api.wigle.net/api/v2/profile/user",
            auth=(api_name, api_token),
            timeout=10,
        )
        if resp.status_code == 200:
            return jsonify({"ok": True, "message": "WiGLE credentials valid"})
        else:
            return jsonify({"ok": False, "error": f"WiGLE returned status {resp.status_code}"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ---------------------------------------------------------------------------
# Device probe fingerprint endpoint
# ---------------------------------------------------------------------------

@app.route("/api/device/<path:mac>/probes")
def api_device_probes(mac):
    """Return all SSIDs a device has probed for — probe fingerprint.

    Used by the LE panel to expand a flagged device's full network list
    so new gov SSIDs can be discovered and added to monitoring.
    """
    db = _get_ro_db()
    try:
        # All SSIDs this device has probed for (from device_ssids table)
        rows = db.execute(
            "SELECT ssid, count, first_seen, last_seen "
            "FROM device_ssids WHERE device_mac = ? "
            "ORDER BY count DESC",
            (mac,),
        ).fetchall()

        # Also get which SSIDs are already in gov_ssids (for UI tagging)
        gov_rows = db.execute(
            "SELECT ssid FROM gov_ssids WHERE active = 1"
        ).fetchall()
        gov_set = {r["ssid"].lower() for r in gov_rows}

        probes = []
        for r in rows:
            ssid = r["ssid"] or ""
            probes.append({
                "ssid": ssid,
                "count": r["count"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "is_monitored": ssid.lower() in gov_set,
            })

        return jsonify({"mac": mac, "probes": probes})
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Gov SSID management endpoints
# ---------------------------------------------------------------------------

@app.route("/api/gov-ssids")
def api_gov_ssids_list():
    """List all user-managed gov/first-responder SSIDs."""
    db = _get_ro_db()
    try:
        rows = db.execute(
            "SELECT id, ssid, label, category, weight, active, created_at "
            "FROM gov_ssids ORDER BY created_at DESC"
        ).fetchall()
        return jsonify({"entries": [dict(r) for r in rows]})
    finally:
        db.close()


@app.route("/api/gov-ssids", methods=["POST"])
def api_gov_ssids_add():
    """Add a gov/first-responder SSID."""
    data = request.get_json(force=True)
    ssid = (data.get("ssid") or "").strip()
    if not ssid:
        return jsonify({"ok": False, "error": "SSID required"}), 400
    label = (data.get("label") or "").strip()
    category = data.get("category", "govt")
    weight = int(data.get("weight", 50))
    weight = max(10, min(weight, 100))  # clamp

    db = _get_rw_db()
    try:
        db.execute(
            "INSERT OR IGNORE INTO gov_ssids (ssid, label, category, weight) VALUES (?, ?, ?, ?)",
            (ssid, label, category, weight),
        )
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/gov-ssids", methods=["DELETE"])
def api_gov_ssids_remove():
    """Remove a gov/first-responder SSID by id or ssid."""
    data = request.get_json(force=True)
    ssid_id = data.get("id")
    ssid = (data.get("ssid") or "").strip()

    db = _get_rw_db()
    try:
        if ssid_id:
            db.execute("DELETE FROM gov_ssids WHERE id = ?", (ssid_id,))
        elif ssid:
            db.execute("DELETE FROM gov_ssids WHERE ssid = ? COLLATE NOCASE", (ssid,))
        else:
            return jsonify({"ok": False, "error": "id or ssid required"}), 400
        db.commit()
        return jsonify({"ok": True})
    finally:
        db.close()


@app.route("/api/interfaces")
def api_interfaces():
    """List available wireless interfaces for the settings dropdown."""
    try:
        from ssid_monitor.scanner import discover_wireless_interfaces
        interfaces = discover_wireless_interfaces()
        return jsonify(interfaces)
    except Exception:
        return jsonify([])


@app.route("/api/settings")
def api_settings_get():
    db = _get_ro_db()
    try:
        # Start with config.toml defaults for device fields, then overlay DB values
        settings = dict(_DEVICE_CONFIG)
        settings.update(get_all_settings(db))
        # Mask Pushover and WiGLE credentials — only show last 4 chars
        for key in ("pushover_user_key", "pushover_api_token", "wigle_api_token"):
            if key in settings and len(settings[key]) > 4:
                settings[key] = "****" + settings[key][-4:]
        return jsonify(settings)
    finally:
        db.close()


@app.route("/api/settings", methods=["POST"])
def api_settings_save():
    db = _get_rw_db()
    try:
        data = request.get_json(force=True)
        allowed_keys = {
            "device_name", "wifi_interface", "scan_interval", "cooldown_min",
            "new_device_alerts",
            "ntfy_enabled", "ntfy_topic", "ntfy_server",
            "pushover_enabled", "pushover_user_key", "pushover_api_token",
            "wigle_api_name", "wigle_api_token",
        }
        for key, value in data.items():
            if key in allowed_keys:
                set_setting(db, key, str(value))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/test-notification", methods=["POST"])
def api_test_notification():
    from ssid_monitor.notifier import send_notification, send_pushover
    data = request.get_json(force=True)
    channel = data.get("channel", "ntfy")

    try:
        if channel == "ntfy":
            ok = send_notification(
                title="DPMB Test",
                message="Test notification from 802.11DPMB dashboard.",
                priority="default",
                tags=["white_check_mark"],
                topic=data.get("topic"),
                server=data.get("server"),
            )
        elif channel == "pushover":
            user_key = data.get("user_key", "")
            api_token = data.get("api_token", "")
            if not user_key or not api_token:
                return jsonify({"ok": False, "error": "Missing Pushover credentials"}), 400
            ok = send_pushover(
                title="DPMB Test",
                message="Test notification from 802.11DPMB dashboard.",
                priority="default",
                user_key=user_key,
                api_token=api_token,
            )
        else:
            return jsonify({"ok": False, "error": f"Unknown channel: {channel}"}), 400

        if ok:
            return jsonify({"ok": True})
        else:
            return jsonify({"ok": False, "error": f"{channel} send failed — check credentials/topic"}), 502
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


def main():
    app.run(host="0.0.0.0", port=5000, debug=False)


if __name__ == "__main__":
    main()
