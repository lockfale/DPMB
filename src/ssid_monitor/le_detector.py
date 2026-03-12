"""Real-time law enforcement signature detection with multi-signal scoring.

Replaces the naive classify_probe() in dashboard.py with a persistent,
real-time scoring engine that evaluates every beacon and probe request as
it arrives from the scanner.

Scoring model:
    Each indicator contributes a weighted score.  The sum is mapped to a
    confidence level (low/medium/high/critical).  Signal trajectory and
    temporal/channel correlation provide bonus weight.

Integration:
    Scanner calls  check_beacon() / check_probe()  on every frame.
    Dashboard calls get_le_activity() / get_le_summary()  for display.
    Events are persisted in the security_events table and pushed via
    notifier.notify_le_signature() for medium+ confidence.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import sqlite3

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Confidence thresholds  (cumulative score -> level)
# ---------------------------------------------------------------------------

CONFIDENCE_CRITICAL = 90
CONFIDENCE_HIGH = 60
CONFIDENCE_MEDIUM = 35
CONFIDENCE_LOW = 15

CONFIDENCE_LEVELS = [
    (CONFIDENCE_CRITICAL, "critical"),
    (CONFIDENCE_HIGH,     "high"),
    (CONFIDENCE_MEDIUM,   "medium"),
    (CONFIDENCE_LOW,      "low"),
]


def _score_to_confidence(score: float) -> str:
    """Map a numeric score to a confidence label."""
    for threshold, label in CONFIDENCE_LEVELS:
        if score >= threshold:
            return label
    return "none"


# ---------------------------------------------------------------------------
# OUI database -- LE/government equipment vendors with weights
# ---------------------------------------------------------------------------
# Weight semantics:
#   HIGH   (40) = almost exclusively LE/gov equipment
#   MEDIUM (20) = used by LE but also in non-LE contexts
#   LOW    (10) = occasionally LE-adjacent

@dataclass(frozen=True, slots=True)
class OUIEntry:
    vendor: str
    weight: int
    note: str = ""


LE_OUI_DB: dict[str, OUIEntry] = {
    # -- Cradlepoint (LE fleet routers -- NetCloud) -- HIGH ----------------
    "00:0c:e6": OUIEntry("Cradlepoint", 40, "IBR/E-series fleet router"),
    "00:14:1b": OUIEntry("Cradlepoint", 40, "Enterprise fleet"),
    "00:30:44": OUIEntry("Cradlepoint", 40, "Fleet router"),
    "e8:ed:05": OUIEntry("Cradlepoint", 40, "NetCloud managed"),
    "00:09:0f": OUIEntry("Cradlepoint", 40, "Legacy OUI"),
    "74:b9:1e": OUIEntry("Cradlepoint", 40, "R-series router"),

    # -- Motorola Solutions (LE radios, MDTs, APX) -- HIGH -----------------
    "00:04:56": OUIEntry("Motorola Solutions", 40, "APX radio system"),
    "00:0b:06": OUIEntry("Motorola Solutions", 40, "Public safety radio"),
    "00:11:43": OUIEntry("Motorola Solutions", 40, "MDT/MCT terminal"),
    "00:14:e8": OUIEntry("Motorola Solutions", 40, "XTS/APX portable"),
    "00:17:4b": OUIEntry("Motorola Solutions", 40, "In-car system"),
    "00:19:2c": OUIEntry("Motorola Solutions", 40, "Public safety"),
    "00:1a:77": OUIEntry("Motorola Solutions", 40, "Fleet management"),
    "00:1c:fb": OUIEntry("Motorola Solutions", 40, "ASTRO radio"),
    "00:23:a2": OUIEntry("Motorola Solutions", 40, "SLN-series"),
    "00:24:ba": OUIEntry("Motorola Solutions", 40, "Infrastructure"),
    "00:1a:de": OUIEntry("Motorola Solutions", 40, "CommandCentral"),
    "40:01:c6": OUIEntry("Motorola Solutions", 40, "Si-series"),
    "cc:46:d6": OUIEntry("Motorola Solutions", 40, "VB400 body cam"),

    # -- L3Harris (LE tactical comms, radios) -- HIGH ----------------------
    "00:90:7f": OUIEntry("L3Harris", 40, "XL/XG radio system"),
    "40:d8:55": OUIEntry("L3Harris", 40, "BeOn/Unity radio"),
    "00:09:02": OUIEntry("L3Harris", 40, "Falcon radio"),
    "00:e0:f7": OUIEntry("L3Harris", 40, "Tactical comms"),

    # -- Cellebrite (forensic extraction devices) -- CRITICAL --------------
    "00:24:c1": OUIEntry("Cellebrite", 50, "UFED forensic device"),
    "b4:cb:57": OUIEntry("Cellebrite", 50, "Touch/4PC forensic"),

    # -- Panasonic (Toughbook -- also non-LE industrial) -- MEDIUM ---------
    "00:07:f6": OUIEntry("Panasonic", 20, "Toughbook/Toughpad"),
    "04:20:9a": OUIEntry("Panasonic", 20, "Toughbook CF-series"),
    "00:80:45": OUIEntry("Panasonic", 20, "Toughbook enterprise"),
    "34:fc:ef": OUIEntry("Panasonic", 20, "Toughbook FZ-series"),
    "80:c5:e6": OUIEntry("Panasonic", 20, "Toughbook G-series"),
    "00:1b:5b": OUIEntry("Panasonic", 20, "Industrial Toughbook"),
    "8c:87:3b": OUIEntry("Panasonic", 20, "Toughpad FZ-M1"),

    # -- Sierra Wireless (fleet cellular modems) -- MEDIUM -----------------
    "00:a0:96": OUIEntry("Sierra Wireless", 20, "AirLink fleet modem"),
    "00:14:3e": OUIEntry("Sierra Wireless", 20, "AirLink MP/RV"),
    "9c:2e:a1": OUIEntry("Sierra Wireless", 20, "RV-series vehicle"),
    "00:a0:d5": OUIEntry("Sierra Wireless", 20, "EM-series module"),

    # -- Getac (rugged LE/military devices) -- MEDIUM ----------------------
    "00:1e:be": OUIEntry("Getac", 20, "Rugged tablet/laptop"),
    "c4:d9:87": OUIEntry("Getac", 20, "F110/V110 rugged"),
    "d4:b8:ff": OUIEntry("Getac", 20, "ZX70 rugged tablet"),

    # -- NetMotion / Absolute (LE VPN appliances) -- MEDIUM ----------------
    "00:0a:e4": OUIEntry("NetMotion Wireless", 20, "Mobility VPN"),
    "00:25:9c": OUIEntry("Absolute/NetMotion", 20, "Fleet VPN appliance"),

    # -- BK Technologies (LE radios, KNG series) -- HIGH -------------------
    "00:13:4a": OUIEntry("BK Technologies", 35, "KNG portable radio"),

    # -- Coban Technologies (patrol car video) -- HIGH ---------------------
    "00:1c:2b": OUIEntry("Coban Technologies", 35, "In-car video system"),

    # -- Digital Ally (body cam / in-car video) -- HIGH --------------------
    "00:22:cf": OUIEntry("Digital Ally", 35, "FirstVu body camera"),

    # -- Axon / TASER (body cam, evidence.com) -- HIGH ---------------------
    "e8:3e:b6": OUIEntry("Axon Enterprise", 35, "Body cam / Signal"),
    "00:26:e4": OUIEntry("Axon Enterprise", 35, "Axon Fleet camera"),
}


# ---------------------------------------------------------------------------
# SSID pattern database with weights
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SSIDPattern:
    regex: re.Pattern
    label: str
    weight: int
    note: str = ""


def _p(pattern: str, label: str, weight: int, note: str = "") -> SSIDPattern:
    """Helper to build a compiled SSIDPattern."""
    return SSIDPattern(re.compile(pattern, re.IGNORECASE), label, weight, note)


# ---------------------------------------------------------------------------
# Fuzzy matching infrastructure
# ---------------------------------------------------------------------------

def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            # insertion, deletion, substitution
            curr_row.append(min(
                prev_row[j + 1] + 1,
                curr_row[j] + 1,
                prev_row[j] + (0 if c1 == c2 else 1),
            ))
        prev_row = curr_row
    return prev_row[-1]



# Seed words for fuzzy SSID matching — (word, base_weight, category)
# These are compared via Levenshtein distance against SSID tokens.
# A near-match (similarity >= 0.75) scores at 60% of base_weight.
LE_FUZZY_SEEDS: list[tuple[str, int, str]] = [
    # Direct LE terms — high base weight
    ("POLICE", 40, "LE agency"),
    ("SHERIFF", 40, "LE agency"),
    ("TROOPER", 40, "LE agency"),
    ("MARSHAL", 40, "LE agency"),
    ("PATROL", 25, "LE function"),
    ("DISPATCH", 30, "LE function"),
    ("CRUISER", 35, "LE vehicle"),
    ("DETECTIVE", 40, "LE role"),
    # Federal
    ("FEDERAL", 30, "Federal"),
    # Equipment vendors (catch misspellings of vendor SSIDs)
    ("CRADLEPOINT", 35, "LE vendor"),
    ("MOTOROLA", 30, "LE vendor"),
    ("FIRSTNET", 35, "Public safety"),
    ("STINGRAY", 50, "Surveillance"),
    ("HAILSTORM", 50, "Surveillance"),
    ("CELLEBRITE", 50, "Forensic"),
    # EMS / Fire
    ("AMBULANCE", 40, "EMS"),
    ("PARAMEDIC", 40, "EMS"),
    ("RESCUE", 30, "EMS/Fire"),
    ("HAZMAT", 35, "Fire"),
    ("ENGINE", 25, "Fire"),
    ("LADDER", 25, "Fire"),
]


# ---------------------------------------------------------------------------
# Troll / joke SSID denylist — common WiFi names that mimic LE agencies.
# Matched case-insensitively BEFORE pattern scoring; any hit → score = 0.
# ---------------------------------------------------------------------------
_TROLL_SSID_PATTERNS: list[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    # "FBI Surveillance Van" and variants
    r"(?i)\bFBI\s+(?:surveillance|van|wifi|party|stakeout|spy|drone)",
    r"(?i)\bNSA\s+(?:listening|surveillance|van|wifi|spy|drone|post)",
    r"(?i)\bCIA\s+(?:safe\s*house|van|wifi|drone|spy|hideout|listening)",
    r"(?i)\bDEA\s+(?:surveillance|van|wifi|stakeout)",
    # Generic troll: agency name + bare number ("FBI 2", "DEA 3")
    r"(?i)^(?:FBI|DEA|ATF|ICE|CBP|DHS|NSA|CIA|SWAT)\s*\d{1,2}$",
    # "Not the FBI" / "Definitely not FBI" / "Totally not the CIA"
    r"(?i)(?:not|definitely\s+not|totally\s+not)\s+(?:the\s+)?(?:FBI|CIA|NSA|DEA|ATF|police|cops)",
    # "FBI Open Up" / "FBI GET DOWN"
    r"(?i)\bFBI\s+(?:open\s+up|get\s+down)",
    # "Police Surveillance" as a joke
    r"(?i)^police\s+surveillance",
    # "Undercover Police" — real UC doesn't broadcast
    r"(?i)\bundercover\s+(?:police|cop|agent)",
    # "SWAT Team WiFi" / "SWAT Van"
    r"(?i)\bSWAT\s+(?:team|van|wifi)",
    # Generic "Surveillance Van" without agency prefix
    r"(?i)^surveillance\s+van$",
    # "Secret CIA WiFi" / "Top Secret FBI"
    r"(?i)(?:secret|top\s+secret)\s+(?:FBI|CIA|NSA|DEA)",
    # "Flowers By Irene" (classic FBI joke)
    r"(?i)flowers\s+by\s+irene",
]]


LE_SSID_PATTERNS: list[SSIDPattern] = [
    # --- Direct LE identifiers (high specificity) -------------------------
    _p(r"\bPD[-_ ]",           "Police Dept",            45, "PD- prefix"),
    _p(r"\bPOLICE\b",          "Police",                 40, "Explicit police keyword"),
    _p(r"\bSHERIFF\b",         "Sheriff",                40),
    _p(r"\bTROOPER\b",         "Trooper",                40),
    _p(r"\bMARSHAL\b",         "Marshal",                40),
    _p(r"\bSWAT\b",            "SWAT",                   45),
    _p(r"\bDETECTIVE\b",       "Detective",              40),
    _p(r"\bHIGHWAY[-_ ]?PATROL\b", "Highway Patrol",     45),
    _p(r"\bSTATE[-_ ]?PATROL\b",   "State Patrol",       45),
    _p(r"\bLEO[-_ ]",          "Law Enforcement",        40),
    _p(r"\bLAPD\b",            "LAPD",                   50),
    _p(r"\bNYPD\b",            "NYPD",                   50),

    # --- Federal identifiers (high specificity) ---------------------------
    _p(r"\bFBI[-_ ]",          "FBI",                    50),
    _p(r"\bDEA[-_ ]",          "DEA",                    50),
    _p(r"\bATF[-_ ]",          "ATF",                    50),
    _p(r"\bICE[-_ ]",          "ICE",                    45),
    _p(r"\bCBP[-_ ]",          "CBP",                    45),
    _p(r"\bUSMS[-_ ]",         "US Marshals",            50),
    _p(r"\bDHS[-_ ]",          "DHS",                    45),
    _p(r"\bFEDERAL\b",         "Federal",                30),

    # --- Radio/dispatch system SSIDs (medium specificity) -----------------
    _p(r"\bMDT[-_ ]?\d",       "Mobile Data Terminal",   35, "MDT-xxx fleet pattern"),
    _p(r"\bCAD[-_ ]?(MOBILE|UNIT|SYS)", "CAD System",    35, "Computer-aided dispatch"),
    _p(r"\bDISPATCH\b",        "Dispatch",               30),
    _p(r"\bCRUISER\b",         "Cruiser",                35),
    _p(r"\bPATROL\b",          "Patrol",                 25),
    _p(r"\bSQUAD\b",           "Squad",                  25),
    _p(r"\bUNIT[-_ ]?\d",      "Unit",                   20, "Ambiguous without OUI"),
    _p(r"\bBEAT[-_ ]?\d",      "Beat",                   25),

    # --- FirstNet / public safety broadband -------------------------------
    _p(r"\bFIRSTNET\b",        "FirstNet",               35, "Public safety LTE"),
    _p(r"FIRSTNET[-_ ]?AP",    "FirstNet AP",            40),
    _p(r"\bPSBB\b",            "Public Safety Broadband", 35),

    # --- Fleet management / Cradlepoint defaults --------------------------
    _p(r"CRADLEPOINT",         "Cradlepoint Fleet",      35),
    _p(r"CP[-_ ]?IBR[-_ ]?\d", "Cradlepoint IBR",        40, "IBR-series vehicle router"),
    _p(r"NETCLOUD",            "NetCloud Managed",        30, "Cradlepoint cloud mgmt"),
    _p(r"CR[-_ ]?\d{3,4}[-_ ]?FLEET", "Cradlepoint Fleet", 35),

    # --- Equipment vendor SSIDs -------------------------------------------
    _p(r"SIERRA[-_ ]?WIRELESS", "Sierra Wireless",       25),
    _p(r"\bL3HARRIS\b",        "L3Harris",               35),
    _p(r"\bMOTOROLA[-_ ]?SOL", "Motorola Solutions",     35),
    _p(r"\bCOBAN\b",           "Coban Video",            35),
    _p(r"\bAXON[-_ ]?(FLEET|BODY|CAM)", "Axon Device",   40),

    # --- Known local first responder SSIDs ----------------------------------
    _p(r"^dcsdata$",            "DC Sheriff",             50, "Known local Sheriff SSID — exact match"),
    _p(r"DigiLab DCSO",         "DC Sheriff Office",      50, "Known local DCSO SSID"),
    _p(r"^DavidsonCountyPublicWifi$", "Davidson County Govt", 40, "Known local county WiFi"),
    _p(r"^Davidson Courthouse$", "Davidson Courthouse",   45, "Known local courthouse WiFi"),
    _p(r"^DC[-_ ]?EMS$",       "DC EMS",                 50, "Known local EMS SSID — exact match"),
    _p(r"\bEMS[-_ ]",          "EMS",                    30, "Emergency Medical Services"),
    _p(r"\bAMBULANCE\b",       "Ambulance",              40),
    _p(r"\bPARAMEDIC\b",       "Paramedic",              40),
    _p(r"\bMEDIC[-_ ]?\d",     "Medic Unit",             35, "Medic-1, Medic-12, etc."),
    _p(r"\bRESCUE[-_ ]?\d",    "Rescue Unit",            35),

    # --- Fire Department ----------------------------------------------------
    _p(r"\bFIRE[-_ ]?DEPT\b",  "Fire Dept",              40),
    _p(r"\bFIRE[-_ ]?STATION\b", "Fire Station",         40),
    _p(r"\bFD[-_ ]\d",         "Fire Dept Unit",         35, "FD-1, FD-12 pattern"),
    _p(r"\bENGINE[-_ ]?\d",    "Engine",                 30, "Engine-3, etc."),
    _p(r"\bLADDER[-_ ]?\d",    "Ladder",                 30),
    _p(r"\bHAZMAT\b",          "HazMat",                 35),

    # --- Government / municipal identifiers (lower specificity) -----------
    _p(r"\bGOV[-_ ]",          "Government",             15),
    _p(r"\bCITY[-_ ]?OF[-_ ]", "Municipal",              10, "Very common, low signal alone"),
    _p(r"\bCOUNTY[-_ ]?OF[-_ ]", "County",               10),
    _p(r"\bCOPS?\b",           "LE Keyword",             15),

    # --- Surveillance / forensic (critical) -------------------------------
    _p(r"\bSTINGRAY\b",        "StingRay IMSI Catcher",  50),
    _p(r"\bHAILSTORM\b",       "Hailstorm CSS",          50),
    _p(r"\bDIRT[-_ ]?BOX\b",   "DRT/DirtBox Aerial",     50),
    _p(r"\bCELLEBRITE\b",      "Cellebrite Forensic",    50),
]


# ---------------------------------------------------------------------------
# Signal trajectory tracker
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class RSSIReading:
    rssi: int
    timestamp: float  # time.monotonic()


@dataclass(slots=True)
class TrajectoryState:
    """Per-entity RSSI history and computed trend."""
    readings: list[RSSIReading] = field(default_factory=list)
    trend: str = "unknown"          # approaching / stable / departing / unknown
    trend_delta: float = 0.0        # average dBm change per reading

    MAX_READINGS = 30
    APPROACH_THRESHOLD = 5.0        # dBm increase over 3+ readings = approaching
    DEPART_THRESHOLD = -5.0         # dBm decrease = departing

    def add_reading(self, rssi: int) -> None:
        self.readings.append(RSSIReading(rssi=rssi, timestamp=time.monotonic()))
        if len(self.readings) > self.MAX_READINGS:
            self.readings = self.readings[-self.MAX_READINGS:]
        self._compute_trend()

    def _compute_trend(self) -> None:
        n = len(self.readings)
        if n < 3:
            self.trend = "unknown"
            self.trend_delta = 0.0
            return

        # Use last 5 readings (or all if fewer) for trend calculation
        recent = self.readings[-min(n, 5):]
        deltas = [
            recent[i].rssi - recent[i - 1].rssi
            for i in range(1, len(recent))
        ]
        avg_delta = sum(deltas) / len(deltas) if deltas else 0.0
        total_change = recent[-1].rssi - recent[0].rssi

        self.trend_delta = avg_delta

        if total_change >= self.APPROACH_THRESHOLD and avg_delta > 0:
            self.trend = "approaching"
        elif total_change <= self.DEPART_THRESHOLD and avg_delta < 0:
            self.trend = "departing"
        else:
            self.trend = "stable"


# ---------------------------------------------------------------------------
# LE event record
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class LEEvent:
    """A scored LE detection event ready for persistence and notification."""
    mac: str
    ssid: str
    score: float
    confidence: str            # low/medium/high/critical
    indicators: list[str]      # human-readable list of what triggered
    rssi: int
    channel: int | None
    trend: str                 # approaching/stable/departing/unknown
    is_new_ap: bool
    timestamp: str             # ISO-8601 UTC


# ---------------------------------------------------------------------------
# Core detector class
# ---------------------------------------------------------------------------

class LEDetector:
    """Real-time multi-signal LE signature scoring engine.

    Thread-safe.  Designed to be instantiated once and shared across
    scanner threads.

    Usage::

        detector = LEDetector(db_path="/var/lib/dpmb/events.db")

        # In scanner beacon handler:
        event = detector.check_beacon(beacon_frame)

        # In scanner probe handler:
        event = detector.check_probe(probe_frame)

        # In dashboard API:
        activity = detector.get_le_activity(minutes=30)
    """

    COOLDOWN_SECONDS = 900  # 15 minutes between re-alerts for same entity

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()

        # In-memory state (not persisted -- rebuilt from live traffic)
        self._trajectories: dict[str, TrajectoryState] = {}
        self._cooldowns: dict[str, float] = {}  # mac -> monotonic expiry

        # Channel correlation tracking: channel -> set of LE macs seen recently
        self._channel_le_macs: dict[int, dict[str, float]] = defaultdict(dict)
        self._CHANNEL_CORRELATION_WINDOW = 120  # seconds

        # User-managed gov SSID cache: {ssid_lower: (label, weight)}
        self._gov_ssid_cache: dict[str, tuple[str, int]] = {}
        self._gov_cache_ts: float = 0.0
        self._GOV_CACHE_TTL = 60.0  # refresh from DB every 60 seconds

    # -- helpers -----------------------------------------------------------

    def _get_db(self) -> "sqlite3.Connection":
        from ssid_monitor.db import get_connection
        return get_connection(self._db_path)

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _is_cooled_down(self, mac: str) -> bool:
        expiry = self._cooldowns.get(mac, 0)
        return time.monotonic() < expiry

    def _set_cooldown(self, mac: str) -> None:
        self._cooldowns[mac] = time.monotonic() + self.COOLDOWN_SECONDS

    def _refresh_gov_cache(self, db: "sqlite3.Connection") -> None:
        """Reload user-managed gov SSIDs from DB if cache is stale."""
        now = time.monotonic()
        if now - self._gov_cache_ts < self._GOV_CACHE_TTL:
            return
        try:
            rows = db.execute(
                "SELECT ssid, label, weight FROM gov_ssids WHERE active = 1"
            ).fetchall()
            self._gov_ssid_cache = {
                r["ssid"].lower(): (r["label"], r["weight"]) for r in rows
            }
            self._gov_cache_ts = now
        except Exception:
            pass  # table may not exist yet on first run

    def _score_gov_ssid(self, ssid: str) -> tuple[float, str | None]:
        """Score SSID against user-managed gov SSID list (cached from DB)."""
        if not ssid:
            return 0.0, None
        entry = self._gov_ssid_cache.get(ssid.lower())
        if entry:
            label, weight = entry
            return float(weight), f"Gov SSID: {label} (user-added, exact match)"
        return 0.0, None

    def _get_trajectory(self, mac: str) -> TrajectoryState:
        if mac not in self._trajectories:
            self._trajectories[mac] = TrajectoryState()
        return self._trajectories[mac]

    def _is_nighttime(self) -> bool:
        """Return True if current local hour is between 22:00 and 06:00."""
        hour = datetime.now().hour  # local time, not UTC
        return hour >= 22 or hour < 6

    def _channel_correlation_count(self, channel: int | None, exclude_mac: str) -> int:
        """Count other LE-flagged MACs seen on the same channel recently."""
        if channel is None:
            return 0
        now = time.monotonic()
        ch_macs = self._channel_le_macs.get(channel, {})
        count = 0
        for mac, ts in list(ch_macs.items()):
            if now - ts > self._CHANNEL_CORRELATION_WINDOW:
                del ch_macs[mac]
            elif mac != exclude_mac:
                count += 1
        return count

    def _record_channel_le(self, channel: int | None, mac: str) -> None:
        if channel is not None:
            self._channel_le_macs[channel][mac] = time.monotonic()

    def _is_new_bssid(self, db: "sqlite3.Connection", bssid: str) -> bool:
        """Check if a BSSID is new (not previously in access_points)."""
        row = db.execute(
            "SELECT beacon_count FROM access_points WHERE bssid = ?",
            (bssid,),
        ).fetchone()
        # Treat as "new" if not in DB or very few beacons (just appeared)
        return row is None or row["beacon_count"] <= 2

    def _is_new_device(self, db: "sqlite3.Connection", mac: str) -> bool:
        """Check if a client device MAC is new (not previously in devices table)."""
        row = db.execute(
            "SELECT probe_count FROM devices WHERE mac = ?",
            (mac,),
        ).fetchone()
        # Treat as "new" if not in DB or very few probes (just appeared)
        return row is None or row["probe_count"] <= 2

    # -- OUI scoring -------------------------------------------------------

    def _score_oui(self, mac: str) -> tuple[float, str | None]:
        """Return (weight, indicator_text) for exact LE OUI match, or (0, None)."""
        if not mac or len(mac) < 8:
            return 0.0, None
        oui = mac[:8].lower()
        entry = LE_OUI_DB.get(oui)
        if entry:
            return float(entry.weight), f"OUI: {entry.vendor} ({entry.note or oui})"
        return 0.0, None

    # -- SSID scoring ------------------------------------------------------

    def _score_ssid(self, ssid: str) -> tuple[float, list[str]]:
        """Return (total_weight, [indicator_texts]) for exact SSID pattern matches."""
        if not ssid:
            return 0.0, []

        # Troll/joke SSID denylist — suppress before any pattern scoring
        for troll_re in _TROLL_SSID_PATTERNS:
            if troll_re.search(ssid):
                return 0.0, []

        total = 0.0
        indicators: list[str] = []
        for pattern in LE_SSID_PATTERNS:
            if pattern.regex.search(ssid):
                total += pattern.weight
                indicators.append(f"SSID pattern: {pattern.label} ({pattern.note or 'matched'})")
                # Take strongest single SSID match to avoid double-counting
                # overlapping patterns (e.g., "POLICE" + "PD-").
                # But allow vendor-specific patterns to stack.
                break
        return total, indicators

    # -- Fuzzy SSID scoring (Levenshtein) ----------------------------------

    def _score_ssid_fuzzy(self, ssid: str) -> tuple[float, list[str]]:
        """Score SSID by Levenshtein distance to known LE seed words.

        Tokenizes the SSID and compares each token against the seed
        dictionary.  A similarity ratio >= 0.75 (e.g., 1 edit on a
        6-char word) scores at 60% of the seed's base weight.

        Only fires if _score_ssid returned 0 (no exact match).

        Returns (weight, [indicator_texts]).
        """
        if not ssid or len(ssid) < 3:
            return 0.0, []

        # Troll/joke SSID denylist — suppress before fuzzy scoring too
        for troll_re in _TROLL_SSID_PATTERNS:
            if troll_re.search(ssid):
                return 0.0, []

        # Tokenize: split on common delimiters
        tokens = re.split(r"[-_ .]+", ssid.upper())
        tokens = [t for t in tokens if len(t) >= 3]  # skip short fragments

        if not tokens:
            return 0.0, []

        best_score = 0.0
        best_indicator = None

        for token in tokens:
            for seed_word, base_weight, category in LE_FUZZY_SEEDS:
                max_len = max(len(token), len(seed_word))
                if max_len == 0:
                    continue

                # Quick reject: if lengths differ by more than 2, skip
                if abs(len(token) - len(seed_word)) > 2:
                    continue

                dist = _levenshtein(token, seed_word)
                similarity = 1.0 - (dist / max_len)

                if similarity >= 0.75 and dist > 0:  # dist>0 excludes exact matches
                    weight = base_weight * 0.60
                    if weight > best_score:
                        best_score = weight
                        best_indicator = (
                            f"Fuzzy SSID: '{token}' ≈ {seed_word} "
                            f"(edit dist={dist}, sim={similarity:.0%}, {category})"
                        )

        indicators = [best_indicator] if best_indicator else []
        return best_score, indicators

    # -- full scoring pipeline ---------------------------------------------

    def _score_frame(
        self,
        mac: str,
        ssid: str,
        rssi: int,
        channel: int | None,
        is_beacon: bool,
        db: "sqlite3.Connection",
    ) -> tuple[float, list[str], bool]:
        """Score a single frame. Returns (score, indicators, is_new_ap)."""

        score = 0.0
        indicators: list[str] = []
        is_new_ap = False

        # Refresh user-managed gov SSID cache
        self._refresh_gov_cache(db)

        # 0. User-managed gov SSID (DB-sourced, highest priority)
        gov_score, gov_ind = self._score_gov_ssid(ssid)
        score += gov_score
        if gov_ind:
            indicators.append(gov_ind)

        # 1. SSID pattern match (exact regex) — skip if gov already matched
        ssid_score = 0.0
        if gov_score == 0:
            ssid_score, ssid_inds = self._score_ssid(ssid)
            score += ssid_score
            indicators.extend(ssid_inds)

        # 1b. Fuzzy SSID match (Levenshtein) — only if no exact match
        if gov_score == 0 and ssid_score == 0:
            fuzzy_ssid_score, fuzzy_inds = self._score_ssid_fuzzy(ssid)
            score += fuzzy_ssid_score
            indicators.extend(fuzzy_inds)

        # 2. OUI match (exact)
        oui_score, oui_ind = self._score_oui(mac)
        score += oui_score
        if oui_ind:
            indicators.append(oui_ind)

        # Bail early if no base indicators at all
        if score == 0:
            return 0.0, [], False

        # 3. Frame-type specific bonuses
        if is_beacon:
            # 3a. New AP appearance (beacon from unknown BSSID with LE OUI)
            if oui_score > 0:
                if self._is_new_bssid(db, mac):
                    is_new_ap = True
                    bonus = 25.0
                    score += bonus
                    indicators.append(f"New AP: previously unseen BSSID (+{bonus:.0f})")
        else:
            # 3b. Probe for LE/gov network — device actively seeking known LE SSID
            # This is a strong behavioral signal: device's configured network list
            # includes a gov/LE network, meaning it's almost certainly LE equipment.
            ssid_matched = (gov_score > 0 or ssid_score > 0)
            if ssid_matched:
                bonus = 15.0
                score += bonus
                indicators.append(f"Probe for LE network: device actively seeking '{ssid}' (+{bonus:.0f})")

            # 3c. New LE device probing — previously unseen device with LE OUI
            if oui_score > 0:
                if self._is_new_device(db, mac):
                    bonus = 20.0
                    score += bonus
                    indicators.append(f"New device: previously unseen LE OUI probing (+{bonus:.0f})")

        # 4. Signal trajectory bonus
        traj = self._get_trajectory(mac)
        traj.add_reading(rssi)
        if traj.trend == "approaching":
            bonus = 15.0
            score += bonus
            indicators.append(f"Trajectory: approaching (delta {traj.trend_delta:+.1f} dBm/reading)")

        # 5. Time-of-day bonus (late night LE OUI = very notable)
        if self._is_nighttime() and oui_score >= 30:
            bonus = 10.0
            score += bonus
            indicators.append(f"Time context: late night LE OUI activity (+{bonus:.0f})")

        # 6. Channel correlation bonus
        corr_count = self._channel_correlation_count(channel, mac)
        if corr_count >= 1:
            bonus = min(corr_count * 10.0, 25.0)
            score += bonus
            indicators.append(
                f"Channel correlation: {corr_count} other LE entity(s) on CH{channel} (+{bonus:.0f})"
            )

        return score, indicators, is_new_ap

    # -- persistence -------------------------------------------------------

    def _persist_event(self, db: "sqlite3.Connection", event: LEEvent) -> None:
        """Write event to security_events and le_detections tables."""
        detail_str = " | ".join(event.indicators)
        if event.trend != "unknown":
            detail_str += f" | trend={event.trend}"
        if event.is_new_ap:
            detail_str += " | NEW_AP"
        detail_str += f" | score={event.score:.0f} conf={event.confidence}"

        db.execute(
            "INSERT INTO security_events (event_type, device_mac, ssid, detail, rssi) "
            "VALUES (?, ?, ?, ?, ?)",
            ("le_signature", event.mac, event.ssid, detail_str, event.rssi),
        )
        # Structured LE detection record
        db.execute(
            "INSERT INTO le_detections "
            "(mac, ssid, confidence, detail, factors, rssi, channel, source_type, trend) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event.mac, event.ssid, event.confidence, detail_str,
             ",".join(event.indicators), event.rssi, event.channel,
             "beacon" if event.is_new_ap else "probe", event.trend),
        )
        db.commit()

    def _notify_event(self, event: LEEvent) -> None:
        """Push notification for medium+ confidence events."""
        try:
            from ssid_monitor.notifier import notify_le_signature

            priority_map = {
                "critical": "urgent",
                "high": "high",
                "medium": "high",
            }
            confidence = event.confidence
            if confidence not in priority_map:
                return

            detail_lines = [
                f"Confidence: {confidence.upper()} (score {event.score:.0f})",
                f"Trend: {event.trend}",
            ]
            detail_lines.extend(event.indicators[:5])

            notify_le_signature(
                ssid=event.ssid or "(no SSID)",
                device_mac=event.mac,
                detail="\n".join(detail_lines),
                rssi=event.rssi,
                db_path=self._db_path,
            )
            logger.info(
                "LE notification sent: %s conf=%s score=%.0f mac=%s",
                event.ssid, confidence, event.score, event.mac,
            )
        except Exception:
            logger.exception("Failed to send LE notification")

    # -- public API: scanner integration -----------------------------------

    def check_beacon(self, bssid: str, ssid: str, rssi: int,
                     channel: int | None = None) -> LEEvent | None:
        """Evaluate a beacon frame for LE signatures.

        Called from the scanner's beacon handler on every captured beacon.

        Args:
            bssid:   AP MAC address.
            ssid:    Network name from the beacon.
            rssi:    Signal strength in dBm.
            channel: Channel number (if known).

        Returns:
            LEEvent if score >= CONFIDENCE_LOW threshold, else None.
        """
        with self._lock:
            return self._evaluate(
                mac=bssid, ssid=ssid, rssi=rssi,
                channel=channel, is_beacon=True,
            )

    def check_probe(self, device_mac: str, ssid: str, rssi: int,
                    channel: int | None = None) -> LEEvent | None:
        """Evaluate a probe request for LE signatures.

        Called from the scanner's probe handler on every captured probe.

        Args:
            device_mac: Source MAC of the probing device.
            ssid:       SSID being probed for.
            rssi:       Signal strength in dBm.
            channel:    Channel number (if known).

        Returns:
            LEEvent if score >= CONFIDENCE_LOW threshold, else None.
        """
        with self._lock:
            return self._evaluate(
                mac=device_mac, ssid=ssid, rssi=rssi,
                channel=channel, is_beacon=False,
            )

    def _evaluate(self, mac: str, ssid: str, rssi: int,
                  channel: int | None, is_beacon: bool) -> LEEvent | None:
        """Core scoring pipeline. Must be called under self._lock."""

        db = self._get_db()
        try:
            score, indicators, is_new_ap = self._score_frame(
                mac=mac, ssid=ssid, rssi=rssi,
                channel=channel, is_beacon=is_beacon, db=db,
            )

            if score < CONFIDENCE_LOW:
                return None

            confidence = _score_to_confidence(score)
            traj = self._get_trajectory(mac)

            event = LEEvent(
                mac=mac,
                ssid=ssid or "",
                score=score,
                confidence=confidence,
                indicators=indicators,
                rssi=rssi,
                channel=channel,
                trend=traj.trend,
                is_new_ap=is_new_ap,
                timestamp=self._now_iso(),
            )

            # Record on channel correlation tracker
            self._record_channel_le(channel, mac)

            # Always update trajectory (already done in _score_frame)

            # Cooldown check: persist always, but only notify once per window
            self._persist_event(db, event)

            if not self._is_cooled_down(mac) and confidence in ("medium", "high", "critical"):
                self._notify_event(event)
                self._set_cooldown(mac)

            logger.info(
                "LE %s: mac=%s ssid=%s score=%.0f conf=%s trend=%s ch=%s%s",
                "BEACON" if is_beacon else "PROBE",
                mac, ssid, score, confidence, traj.trend, channel,
                " NEW_AP" if is_new_ap else "",
            )

            return event

        except Exception:
            logger.exception("Error in LE evaluation for mac=%s ssid=%s", mac, ssid)
            return None
        finally:
            try:
                db.close()
            except Exception:
                pass

    # -- public API: batch processing for scan cycles ----------------------

    def process_beacons(self, beacons: list) -> list[LEEvent]:
        """Evaluate a batch of BeaconFrame namedtuples from a scan cycle.

        Convenience wrapper for integrating with the existing scan loop.

        Args:
            beacons: List of scanner.BeaconFrame namedtuples.

        Returns:
            List of LEEvent objects for any LE-flagged beacons.
        """
        events: list[LEEvent] = []
        for b in beacons:
            ev = self.check_beacon(
                bssid=b.bssid, ssid=b.ssid,
                rssi=b.rssi, channel=b.channel,
            )
            if ev:
                events.append(ev)
        return events

    def process_probes(self, probes: list) -> list[LEEvent]:
        """Evaluate a batch of ProbeFrame namedtuples from a scan cycle.

        Args:
            probes: List of scanner.ProbeFrame namedtuples.

        Returns:
            List of LEEvent objects for any LE-flagged probes.
        """
        events: list[LEEvent] = []
        for p in probes:
            ev = self.check_probe(
                device_mac=p.device_mac, ssid=p.ssid,
                rssi=p.rssi, channel=p.channel,
            )
            if ev:
                events.append(ev)
        return events

    # -- public API: dashboard queries -------------------------------------

    def get_le_activity(self, minutes: int = 30, limit: int = 100) -> list[dict]:
        """Return recent LE signature events for the dashboard.

        Args:
            minutes: How far back to look (default 30 min).
            limit:   Maximum number of events to return.

        Returns:
            List of dicts with keys: mac, ssid, detail, rssi, seen_at,
            confidence, score, trend.
        """
        db = self._get_db()
        try:
            rows = db.execute(
                "SELECT device_mac, ssid, detail, rssi, seen_at "
                "FROM security_events "
                "WHERE event_type = 'le_signature' "
                "AND seen_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) "
                "ORDER BY seen_at DESC LIMIT ?",
                (f"-{minutes} minutes", limit),
            ).fetchall()

            results = []
            for r in rows:
                detail = r["detail"] or ""
                # Parse confidence and score from detail string
                conf = "low"
                score_val = 0.0
                trend_val = "unknown"

                conf_match = re.search(r"conf=(\w+)", detail)
                if conf_match:
                    conf = conf_match.group(1)
                score_match = re.search(r"score=(\d+)", detail)
                if score_match:
                    score_val = float(score_match.group(1))
                trend_match = re.search(r"trend=(\w+)", detail)
                if trend_match:
                    trend_val = trend_match.group(1)

                mac = r["device_mac"] or ""
                traj = self._trajectories.get(mac)

                results.append({
                    "mac": mac,
                    "ssid": r["ssid"] or "",
                    "detail": detail,
                    "rssi": r["rssi"],
                    "seen_at": r["seen_at"],
                    "confidence": conf,
                    "score": score_val,
                    "trend": traj.trend if traj else trend_val,
                    "is_new_ap": "NEW_AP" in detail,
                })
            return results
        finally:
            try:
                db.close()
            except Exception:
                pass

    def get_le_summary(self, minutes: int = 5) -> dict:
        """Return aggregate LE summary stats for dashboard header.

        Args:
            minutes: Time window for counts.

        Returns:
            Dict with keys: total_events, critical_count, high_count,
            medium_count, low_count, unique_macs, active_trends.
        """
        db = self._get_db()
        try:
            rows = db.execute(
                "SELECT device_mac, detail FROM security_events "
                "WHERE event_type = 'le_signature' "
                "AND seen_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) ",
                (f"-{minutes} minutes",),
            ).fetchall()

            summary: dict = {
                "total_events": len(rows),
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "unique_macs": len({r["device_mac"] for r in rows if r["device_mac"]}),
                "active_trends": {},
            }

            for r in rows:
                detail = r["detail"] or ""
                conf_match = re.search(r"conf=(\w+)", detail)
                if conf_match:
                    c = conf_match.group(1)
                    key = f"{c}_count"
                    if key in summary:
                        summary[key] += 1

            # Add live trajectory data for active entities
            for mac, traj in self._trajectories.items():
                if traj.readings and (time.monotonic() - traj.readings[-1].timestamp < 300):
                    summary["active_trends"][mac] = {
                        "trend": traj.trend,
                        "delta": round(traj.trend_delta, 1),
                        "last_rssi": traj.readings[-1].rssi,
                        "reading_count": len(traj.readings),
                    }

            return summary
        finally:
            try:
                db.close()
            except Exception:
                pass

    def get_trajectory(self, mac: str) -> dict | None:
        """Return the current trajectory state for a specific MAC/BSSID.

        Args:
            mac: The MAC address to look up.

        Returns:
            Dict with trend info, or None if no trajectory data exists.
        """
        traj = self._trajectories.get(mac)
        if not traj or not traj.readings:
            return None
        return {
            "mac": mac,
            "trend": traj.trend,
            "trend_delta": round(traj.trend_delta, 1),
            "reading_count": len(traj.readings),
            "last_rssi": traj.readings[-1].rssi,
            "readings": [
                {"rssi": r.rssi, "age_sec": round(time.monotonic() - r.timestamp, 1)}
                for r in traj.readings[-10:]  # last 10 for display
            ],
        }

    # -- maintenance -------------------------------------------------------

    def cleanup_stale_state(self, max_age_sec: int = 3600) -> int:
        """Purge in-memory state for entities not seen in max_age_sec.

        Should be called periodically (e.g., every 10 minutes) to prevent
        unbounded memory growth.

        Returns:
            Number of entries purged.
        """
        now = time.monotonic()
        purged = 0

        with self._lock:
            # Purge trajectories
            stale_macs = [
                mac for mac, traj in self._trajectories.items()
                if traj.readings and (now - traj.readings[-1].timestamp) > max_age_sec
            ]
            for mac in stale_macs:
                del self._trajectories[mac]
                purged += 1

            # Purge expired cooldowns
            expired = [mac for mac, exp in self._cooldowns.items() if now > exp]
            for mac in expired:
                del self._cooldowns[mac]

            # Purge stale channel correlation entries
            for ch_macs in self._channel_le_macs.values():
                stale = [m for m, ts in ch_macs.items() if now - ts > self._CHANNEL_CORRELATION_WINDOW]
                for m in stale:
                    del ch_macs[m]

        if purged:
            logger.debug("LE detector: purged %d stale trajectory entries", purged)
        return purged


# ---------------------------------------------------------------------------
# Module-level convenience: singleton detector instance
# ---------------------------------------------------------------------------

_detector: LEDetector | None = None
_detector_lock = threading.Lock()


def get_detector(db_path: str | None = None) -> LEDetector:
    """Get or create the singleton LEDetector instance.

    Args:
        db_path: Database path. Required on first call, optional after.

    Returns:
        The shared LEDetector instance.

    Raises:
        RuntimeError: If called without db_path and no instance exists.
    """
    global _detector
    with _detector_lock:
        if _detector is None:
            if db_path is None:
                raise RuntimeError(
                    "LEDetector not initialized -- call get_detector(db_path) first"
                )
            _detector = LEDetector(db_path)
            logger.info("LE detector initialized with db_path=%s", db_path)
        return _detector


def reset_detector() -> None:
    """Reset the singleton (primarily for testing)."""
    global _detector
    with _detector_lock:
        _detector = None
