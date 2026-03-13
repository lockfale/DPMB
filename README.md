# 802.11DPMB

**Don't Probe Me Bro** -- targeted 802.11 probe monitoring 

---

## What It Does

- Passive 802.11 beacon and probe request monitoring
- SSID watchlist with real-time alerts on detection
- Law enforcement / government device detection via SSID patterns and OUI fingerprinting
- Wireless intrusion detection (WIDS) — deauth floods, rogue APs, evil twin detection
- Network health monitoring with signal quality tracking
- Device tracking with first-seen/last-seen presence timeline
- Dual notification channels (ntfy.sh + Pushover) configurable from the dashboard
- Live web dashboard with guided onboarding tour
- WPA handshake capture (passive EAPOL collection, hc22000 for hashcat)
- Hidden SSID decloaking (passive correlation + active deauth)
- Auto-discovery of wireless interfaces — zero-config setup
- USB WiFi adapter hot-swap via udev auto-restart
- Daily heartbeat notifications

## Requirements

- Python 3.11+
- Linux (tested on Ubuntu/Debian)
- Root access (required for monitor mode and raw packet capture)
- A **monitor-mode capable USB WiFi adapter** (see below)

### WiFi Adapter Selection

DPMB requires an adapter whose driver supports monitor mode and packet injection under Linux. Not all WiFi adapters support this — most built-in laptop cards do not.

| Chipset | Example Adapter | Driver | Band | Notes |
|---------|----------------|--------|------|-------|
| Atheros AR9271 | Alfa AWUS036NHA | `ath9k_htc` | 2.4 GHz | Gold standard. Works out of the box on every distro. |
| MediaTek MT7612U | Alfa AWUS036ACM | `mt76` | 2.4 + 5 GHz | Best dual-band option. Native kernel driver. |
| Ralink RT3070 | Alfa AWUS036NH | `rt2800usb` | 2.4 GHz | Solid, well-supported. Tested with VM passthrough. |
| Ralink RT5372 | Panda PAU06 | `rt2800usb` | 2.4 GHz | Cheap and widely available. |
| Realtek RTL8812AU | Alfa AWUS036ACH | `rtl8812au` | 2.4 + 5 GHz | Requires [out-of-tree driver](https://github.com/aircrack-ng/rtl8812au). |

**Recommendation:** Alfa AWUS036ACM (MT7612U) for dual-band or Alfa AWUS036NHA (AR9271) for 2.4 GHz only. Both use in-kernel drivers with zero extra setup.

DPMB auto-detects your wireless interface on startup. If multiple adapters are present, it prefers one already in monitor mode, then falls back to the first wireless interface found. You can also set a specific interface in the config.

## Quick Start

```bash
git clone https://github.com/lockfale/DPMB.git
cd DPMB
sudo bash setup.sh
```

On first launch, DPMB auto-detects your wireless adapter and puts it into monitor mode. No manual interface configuration required.

## Configuration

Settings can be managed two ways:

1. **Dashboard UI** — click the gear icon to configure device and notification settings
2. **Config file** — edit `/etc/dpmb/config.toml` directly

| Field | Description | Required |
|-------|-------------|----------|
| `device_id` | Unique identifier for this sensor | No (defaults to hostname) |
| `wifi_interface` | Wireless interface to use | No (auto-detected if blank) |
| `scan_interval_sec` | Seconds between scan cycles | No (default: 10) |
| `cooldown_min` | Minutes before re-alerting on the same SSID | No (default: 60) |
| `webhook_url` | Endpoint for detection alerts and heartbeats | Yes |
| `heartbeat_hour` | Hour of day (0-23) to send the daily heartbeat | No (default: 8) |
| `log_level` | Logging verbosity (`debug`, `info`, `warning`, `error`) | No (default: info) |
| `db_path` | Path to the SQLite database file | No (default: `/var/lib/dpmb/events.db`) |

## Dashboard

The web dashboard runs on port 5000 with nine tabs:

| Tab | Description |
|-----|-------------|
| **Health** | Network health overview — signal strength, channel utilization, AP stability |
| **Live** | Real-time probe request feed with MAC, SSID, RSSI, and channel |
| **WIDS** | Wireless intrusion detection alerts — deauth floods, rogue APs, evil twins |
| **Watchlist** | Manage watched SSIDs and owned networks |
| **Devices** | Tracked client devices with first-seen, last-seen, and vendor lookup |
| **Timeline** | Temporal view of device presence and activity patterns |
| **Neighbors** | Observed access points with SSID, BSSID, channel, signal, and encryption |
| **LE Activity** | Law enforcement / government device detections with confidence scores |
| **Intel** | SSID intelligence — hidden AP correlation, OUI analysis |

### First-Time Tour

On first visit, a guided 9-step tour walks through every dashboard feature. The tour can be restarted by clearing `dpmb_tour_completed` from browser localStorage.

### Settings

Click the gear icon to open the settings drawer:

- **Device** — device name, WiFi interface (auto-populated dropdown), scan interval, alert cooldown
- **ntfy.sh** — enable/disable, topic, server URL, test button
- **Pushover** — enable/disable, user key, application API token, test button

## Notifications

DPMB supports two push notification channels, configurable from the dashboard:

| Channel | Setup |
|---------|-------|
| **ntfy.sh** | Set a topic name. Free, no account required. Uses ntfy.sh by default or your own server. |
| **Pushover** | Enter your User Key and an Application API Token (register at pushover.net/apps). |

Both channels can be enabled simultaneously. Each notification type fires on both enabled channels.

### Alert Types

| Alert | Trigger |
|-------|---------|
| Watchlist match | A watched SSID is detected in a beacon or probe |
| New device | A previously unseen client MAC appears |
| Deauth burst | Deauthentication flood detected (WIDS) |
| WIDS alert | Rogue AP, evil twin, or other wireless intrusion event |
| Health degradation | Signal quality drop, channel interference spike |
| LE signature | Law enforcement device pattern matched |
| Heartbeat | Daily status report (configurable hour) |

## CLI Reference

| Command | Description |
|---------|-------------|
| `dpmb start` | Start monitoring daemon (auto-detects WiFi adapter) |
| `dpmb dashboard` | Launch web dashboard on port 5000 |
| `dpmb init` | Interactive first-time setup (auto-detects interfaces) |
| `dpmb status` | Check service status |
| `dpmb watch add <SSID>` | Add SSID to watchlist |
| `dpmb watch remove <SSID>` | Remove SSID from watchlist |
| `dpmb watch list` | List all watched SSIDs |
| `dpmb watch enable <SSID>` | Enable a watchlist entry |
| `dpmb watch disable <SSID>` | Disable a watchlist entry |
| `dpmb log` | Query detection events |
| `dpmb log export` | Export events (CSV or JSON) |
| `dpmb heartbeat` | Send heartbeat notification |
| `dpmb purge --before <DATE> --confirm` | Delete old events |
| `dpmb test-webhook` | Test webhook delivery |

## Architecture

| Module | Purpose |
|--------|---------|
| `scanner.py` | Core packet capture, monitor mode, device tracking, WIDS, health monitoring |
| `le_detector.py` | Multi-signal LE device scoring engine |
| `le_signatures.py` | LE SSID patterns and OUI database |
| `detector.py` | Probe-to-watchlist matching |
| `dashboard.py` | Flask web UI with settings and onboarding tour |
| `notifier.py` | Dual-channel notifications (ntfy.sh + Pushover) |
| `handshake.py` | WPA EAPOL capture and hc22000 output |
| `watchlist.py` | SSID watchlist CRUD operations |
| `alerter.py` | Webhook delivery |
| `heartbeat.py` | Daily status reporting |
| `config.py` | TOML configuration loader with validation |
| `db.py` | SQLite schema, migrations, and settings store |
| `oui.py` | MAC vendor lookup database |
| `_decloak.py` | Hidden SSID decloaking (passive) |
| `_decloak_active.py` | Hidden SSID decloaking (active deauth) |

## License

BEER-Ware License (Revision 34) -- see [LICENSE](LICENSE).
