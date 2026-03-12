"""One-shot hidden SSID decloak — passive correlation from AP history + probe logs."""
import sqlite3

db = sqlite3.connect("/var/lib/dpmb/events.db", timeout=5)
db.row_factory = sqlite3.Row

# Find hidden SSIDs (empty SSID) and their BSSIDs
hidden = db.execute(
    "SELECT bssid, channel, encryption, beacon_count, avg_rssi FROM access_points WHERE ssid = ''"
).fetchall()
print(f"Hidden SSID APs: {len(hidden)}")
for h in hidden:
    rssi = round(h['avg_rssi']) if h['avg_rssi'] else '?'
    print(f"  BSSID: {h['bssid']} | CH{h['channel']} | {h['encryption']} | beacons={h['beacon_count']} | RSSI={rssi}")

print()
print("--- Passive decloak (from ap_history probe responses) ---")
decloaked = 0
for h in hidden:
    revealed = db.execute(
        "SELECT DISTINCT ssid FROM ap_history WHERE bssid = ? AND ssid != '' AND ssid IS NOT NULL",
        (h['bssid'],)
    ).fetchall()
    if revealed:
        ssids = [r['ssid'] for r in revealed]
        print(f"  {h['bssid']} -> {ssids}")
        # Update the AP record with the revealed SSID
        db.execute("UPDATE access_points SET ssid = ? WHERE bssid = ? AND ssid = ''", (ssids[0], h['bssid']))
        decloaked += 1

db.commit()
print(f"\nDecloaked {decloaked} of {len(hidden)} hidden APs")

# Show remaining hidden
remaining = db.execute("SELECT bssid, channel, encryption FROM access_points WHERE ssid = ''").fetchall()
if remaining:
    print(f"\nStill hidden ({len(remaining)}):")
    for r in remaining:
        print(f"  {r['bssid']} | CH{r['channel']} | {r['encryption']}")
else:
    print("\nAll APs now have SSIDs!")

db.close()
