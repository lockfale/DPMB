"""LE / Government equipment signature database.

Shared between le_detector.py (scanner-time classification) and
dashboard.py (display-time fallback classification).
"""

import re

# ---------------------------------------------------------------------------
# SSID patterns (case-insensitive regex) with confidence weights
#   weight: 1 = weak (common words), 2 = moderate, 3 = strong LE indicator
# ---------------------------------------------------------------------------
LE_SSID_PATTERNS = [
    # Direct LE identifiers — weight 3
    (r"\bPOLICE\b", "Police", 3),
    (r"\bSHERIFF\b", "Sheriff", 3),
    (r"\bSTATE[-_ ]?POLICE\b", "State Police", 3),
    (r"\bHIGHWAY[-_ ]?PATROL\b", "Highway Patrol", 3),
    (r"\bCHP\b", "CHP", 3),
    (r"\bSWAT\b", "SWAT", 3),
    (r"\bDETECTIVE\b", "Detective", 3),
    (r"\bMARSHAL\b", "Marshal", 3),
    (r"\bTROOPER\b", "Trooper", 3),
    (r"\bLEO[-_ ]", "Law Enforcement", 3),

    # Federal agencies — weight 3
    (r"\bFBI\b", "FBI", 3),
    (r"\bDEA\b", "DEA", 3),
    (r"\bATF\b", "ATF", 3),
    (r"\bICE[-_ ]", "ICE", 3),
    (r"\bCBP[-_ ]", "CBP", 3),
    (r"\bDHS[-_ ]", "DHS", 3),
    (r"\bFEDERAL\b", "Federal", 3),
    (r"\bUSMS\b", "US Marshals", 3),
    (r"\bSECRET[-_ ]?SERVICE\b", "Secret Service", 3),

    # MDT / fleet patterns — weight 2
    (r"\bPD[-_ ]", "Police Dept", 2),
    (r"\bMDT[-_ ]?\d", "Mobile Data Terminal", 2),
    (r"\bUNIT[-_ ]?\d", "Unit", 2),
    (r"\bCRUISER\b", "Cruiser", 2),
    (r"\bPATROL\b", "Patrol", 2),
    (r"\bSQUAD\b", "Squad", 2),
    (r"\bDISPATCH\b", "Dispatch", 2),
    (r"\bFIRSTNET\b", "FirstNet", 2),
    (r"\bCAD[-_ ]?MOBILE\b", "CAD Mobile", 2),
    (r"\bIN[-_ ]?CAR[-_ ]?VIDEO\b", "In-Car Video", 2),
    (r"\bBODY[-_ ]?CAM\b", "Body Camera", 2),
    (r"\bALPR\b", "License Plate Reader", 2),
    (r"\bLPR[-_ ]", "License Plate Reader", 2),

    # LE equipment vendors — weight 2
    (r"CRADLEPOINT", "Cradlepoint (LE Fleet)", 2),
    (r"SIERRA[-_ ]?WIRELESS", "Sierra Wireless", 2),
    (r"\bL3HARRIS\b", "L3Harris", 2),
    (r"\bMOTOROLA[-_ ]?SOL", "Motorola Solutions", 2),
    (r"\bNETMOTION\b", "NetMotion VPN", 2),

    # Cradlepoint NetCloud defaults — weight 2
    (r"^CP[-_ ]?\d{3,}", "Cradlepoint Default SSID", 2),
    (r"^IBR\d{3,}", "Cradlepoint IBR Router", 2),
    (r"^COR[-_ ]?IBR", "Cradlepoint COR/IBR", 2),

    # Known local first responder SSIDs — weight 3
    (r"^dcsdata$", "DC Sheriff (exact)", 3),
    (r"DigiLab DCSO", "DC Sheriff Office", 3),
    (r"^DavidsonCountyPublicWifi$", "Davidson County Govt", 2),
    (r"^Davidson Courthouse$", "Davidson Courthouse", 2),
    (r"^DC[-_ ]?EMS$", "DC EMS (exact)", 3),
    (r"\bEMS\b", "EMS", 2),
    (r"\bAMBULANCE\b", "Ambulance", 3),
    (r"\bPARAMEDIC\b", "Paramedic", 3),
    (r"\bMEDIC[-_ ]?\d", "Medic Unit", 2),
    (r"\bRESCUE\b", "Rescue", 2),

    # Fire Department — weight 2-3
    (r"\bFIRE[-_ ]?DEPT\b", "Fire Dept", 3),
    (r"\bFIRE[-_ ]?STATION\b", "Fire Station", 3),
    (r"\bFD[-_ ]\d", "Fire Dept Unit", 2),
    (r"\bENGINE[-_ ]?\d", "Engine", 2),
    (r"\bLADDER[-_ ]?\d", "Ladder", 2),
    (r"\bHAZMAT\b", "HazMat", 2),

    # Weak / ambiguous — weight 1
    (r"\bCOPS?\b", "LE Keyword", 1),
    (r"\bGOV[-_ ]", "Government", 1),
    (r"\bCITY[-_ ]?OF[-_ ]", "Municipal", 1),
    (r"\bCOUNTY[-_ ]?OF[-_ ]", "County", 1),
]

LE_SSID_COMPILED = [(re.compile(p, re.IGNORECASE), label, weight) for p, label, weight in LE_SSID_PATTERNS]

# ---------------------------------------------------------------------------
# OUI (MAC vendor) prefixes with confidence weights
#   weight: 1 = weak (also used widely in non-LE), 2 = moderate, 3 = strong
# ---------------------------------------------------------------------------
LE_OUI_PREFIXES = {
    # Cradlepoint — primary LE fleet router vendor — weight 3
    "00:0c:e6": ("Cradlepoint", 3),
    "00:14:1b": ("Cradlepoint", 3),
    "00:30:44": ("Cradlepoint", 3),
    "e8:ed:05": ("Cradlepoint", 3),
    "88:e9:fe": ("Cradlepoint", 3),

    # Motorola Solutions — LE radios, MDTs — weight 3
    "00:04:56": ("Motorola Solutions", 3),
    "00:0b:06": ("Motorola Solutions", 3),
    "00:11:43": ("Motorola Solutions", 3),
    "00:14:e8": ("Motorola Solutions", 3),
    "00:17:4b": ("Motorola Solutions", 3),
    "00:19:2c": ("Motorola Solutions", 3),
    "00:1a:77": ("Motorola Solutions", 3),
    "00:1c:fb": ("Motorola Solutions", 3),
    "00:23:a2": ("Motorola Solutions", 3),
    "00:24:ba": ("Motorola Solutions", 3),
    "cc:46:d6": ("Motorola Solutions", 3),
    "40:f4:13": ("Motorola Solutions", 3),

    # L3Harris — LE/mil comms — weight 3
    "00:90:7f": ("L3Harris", 3),
    "40:d8:55": ("L3Harris", 3),

    # Sierra Wireless — fleet modems — weight 2
    "00:a0:96": ("Sierra Wireless", 2),
    "00:14:3e": ("Sierra Wireless", 2),
    "9c:2e:a1": ("Sierra Wireless", 2),

    # Getac — rugged LE laptops/tablets — weight 2
    "00:08:ca": ("Getac", 2),
    "00:0e:c4": ("Getac", 2),

    # Panasonic — Toughbook (LE + non-LE) — weight 1
    "00:07:f6": ("Panasonic (Toughbook)", 1),
    "04:20:9a": ("Panasonic (Toughbook)", 1),
    "00:80:45": ("Panasonic (Toughbook)", 1),
    "34:fc:ef": ("Panasonic (Toughbook)", 1),
    "80:c5:e6": ("Panasonic (Toughbook)", 1),

    # Cellebrite — forensic devices (rare on WiFi) — weight 3
    "00:1e:2a": ("Cellebrite", 3),
}

# Flat vendor lookup (no weights) for backward compat with dashboard classify_probe
LE_OUI_FLAT = {k: v[0] for k, v in LE_OUI_PREFIXES.items()}

# Simple pattern list (no weights) for backward compat
LE_SSID_FLAT = [(p, label) for p, label, _ in LE_SSID_PATTERNS]
