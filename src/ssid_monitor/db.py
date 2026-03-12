"""SQLite database module — connection factory, schema creation, WAL mode."""

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 5

SCHEMA_SQL = """
-- ── Core tables ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid TEXT NOT NULL UNIQUE,
    active INTEGER NOT NULL DEFAULT 1,
    watch_type TEXT NOT NULL DEFAULT 'alert',
    label TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS detection_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid TEXT NOT NULL,
    detected_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    device_id TEXT NOT NULL,
    rssi INTEGER NOT NULL,
    device_mac TEXT,
    channel INTEGER,
    alert_sent INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid TEXT NOT NULL,
    triggered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    device_id TEXT NOT NULL,
    webhook_status INTEGER NOT NULL,
    webhook_response TEXT,
    cooldown_until TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS failed_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    retry_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS probe_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid TEXT NOT NULL,
    device_mac TEXT NOT NULL,
    rssi INTEGER NOT NULL,
    channel INTEGER,
    seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    matched INTEGER NOT NULL DEFAULT 0
);

-- ── Device tracking ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    probe_count INTEGER NOT NULL DEFAULT 0,
    label TEXT,
    is_known INTEGER NOT NULL DEFAULT 0,
    avg_rssi REAL,
    min_rssi INTEGER,
    max_rssi INTEGER,
    is_randomized INTEGER NOT NULL DEFAULT 0
);

-- ── Device SSID fingerprint (which networks each device probes for) ─────
CREATE TABLE IF NOT EXISTS device_ssids (
    device_mac TEXT NOT NULL,
    ssid TEXT NOT NULL,
    first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (device_mac, ssid)
);

-- ── Presence log (arrive / depart events per device) ────────────────────
CREATE TABLE IF NOT EXISTS presence_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_mac TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    rssi INTEGER,
    ssid TEXT
);

-- ── Security events (deauth, evil twin, new device, LE signature) ───────
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    device_mac TEXT,
    ssid TEXT,
    detail TEXT,
    seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    rssi INTEGER
);

-- ── Access points (beacon / probe-response inventory) ────────────────────
CREATE TABLE IF NOT EXISTS access_points (
    bssid TEXT PRIMARY KEY,
    ssid TEXT NOT NULL DEFAULT '',
    channel INTEGER,
    encryption TEXT NOT NULL DEFAULT 'Unknown',
    first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    beacon_count INTEGER NOT NULL DEFAULT 0,
    avg_rssi REAL,
    min_rssi INTEGER,
    max_rssi INTEGER,
    is_trusted INTEGER NOT NULL DEFAULT 0,
    label TEXT
);

-- ── AP history (track changes in channel / encryption over time) ─────────
CREATE TABLE IF NOT EXISTS ap_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid TEXT NOT NULL,
    ssid TEXT,
    channel INTEGER,
    encryption TEXT,
    rssi INTEGER,
    seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- ── Client ↔ AP associations ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS client_associations (
    device_mac TEXT NOT NULL,
    bssid TEXT NOT NULL,
    first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (device_mac, bssid)
);

-- ── WIDS alerts (structured threat alerts) ───────────────────────────────
CREATE TABLE IF NOT EXISTS wids_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'high',
    bssid TEXT,
    device_mac TEXT,
    ssid TEXT,
    detail TEXT,
    seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    acknowledged INTEGER NOT NULL DEFAULT 0
);

-- ── Network health snapshots (per-owned-BSSID per scan cycle) ────────────
CREATE TABLE IF NOT EXISTS network_health (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid TEXT NOT NULL,
    ssid TEXT,
    rssi INTEGER,
    channel INTEGER,
    beacon_count_cycle INTEGER NOT NULL DEFAULT 0,
    channel_ap_count INTEGER NOT NULL DEFAULT 0,
    channel_client_count INTEGER NOT NULL DEFAULT 0,
    noise_floor_est INTEGER,
    snr_est INTEGER,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- ── LE / Government equipment detections (scanner-sourced) ────────────────
CREATE TABLE IF NOT EXISTS le_detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    ssid TEXT,
    confidence TEXT NOT NULL DEFAULT 'low',
    detail TEXT,
    factors TEXT,
    rssi INTEGER,
    channel INTEGER,
    source_type TEXT,
    trend TEXT,
    seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- ── User-managed gov/first-responder SSIDs ─────────────────────────────
CREATE TABLE IF NOT EXISTS gov_ssids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid TEXT NOT NULL UNIQUE COLLATE NOCASE,
    label TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'govt',
    weight INTEGER NOT NULL DEFAULT 50,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- ── Notification settings (key/value store) ─────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- ── Indexes ──────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_detection_ssid ON detection_events(ssid);
CREATE INDEX IF NOT EXISTS idx_detection_time ON detection_events(detected_at);
CREATE INDEX IF NOT EXISTS idx_alerts_ssid_cooldown ON alerts(ssid, cooldown_until);
CREATE INDEX IF NOT EXISTS idx_probe_log_time ON probe_log(seen_at);
CREATE INDEX IF NOT EXISTS idx_probe_log_mac ON probe_log(device_mac);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_device_ssids_mac ON device_ssids(device_mac);
CREATE INDEX IF NOT EXISTS idx_presence_mac ON presence_log(device_mac);
CREATE INDEX IF NOT EXISTS idx_presence_time ON presence_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_time ON security_events(seen_at);
CREATE INDEX IF NOT EXISTS idx_security_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_ap_bssid ON access_points(bssid);
CREATE INDEX IF NOT EXISTS idx_ap_ssid ON access_points(ssid);
CREATE INDEX IF NOT EXISTS idx_ap_history_bssid ON ap_history(bssid);
CREATE INDEX IF NOT EXISTS idx_ap_history_time ON ap_history(seen_at);
CREATE INDEX IF NOT EXISTS idx_client_assoc_mac ON client_associations(device_mac);
CREATE INDEX IF NOT EXISTS idx_client_assoc_bssid ON client_associations(bssid);
CREATE INDEX IF NOT EXISTS idx_wids_time ON wids_alerts(seen_at);
CREATE INDEX IF NOT EXISTS idx_wids_type ON wids_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_health_bssid ON network_health(bssid);
CREATE INDEX IF NOT EXISTS idx_health_time ON network_health(timestamp);
CREATE INDEX IF NOT EXISTS idx_le_mac ON le_detections(mac);
CREATE INDEX IF NOT EXISTS idx_le_time ON le_detections(seen_at);
CREATE INDEX IF NOT EXISTS idx_le_confidence ON le_detections(confidence);
"""


def get_connection(db_path: str) -> sqlite3.Connection:
    """Create a SQLite connection with WAL mode and appropriate pragmas."""
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Run forward-only migrations for schema changes to existing tables."""
    # v4: add watch_type and label to watchlist
    cols = {r[1] for r in conn.execute("PRAGMA table_info(watchlist)").fetchall()}
    if "watch_type" not in cols:
        conn.execute("ALTER TABLE watchlist ADD COLUMN watch_type TEXT NOT NULL DEFAULT 'alert'")
    if "label" not in cols:
        conn.execute("ALTER TABLE watchlist ADD COLUMN label TEXT")

    # v6: add is_randomized to devices (MAC randomization detection)
    dev_cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)").fetchall()}
    if "is_randomized" not in dev_cols:
        conn.execute("ALTER TABLE devices ADD COLUMN is_randomized INTEGER NOT NULL DEFAULT 0")

    # v7: le_detections table (scanner-sourced LE equipment tracking)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "le_detections" not in tables:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS le_detections ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "mac TEXT NOT NULL, ssid TEXT, confidence TEXT NOT NULL DEFAULT 'low', "
            "detail TEXT, factors TEXT, rssi INTEGER, channel INTEGER, "
            "source_type TEXT, trend TEXT, "
            "seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')))"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_le_mac ON le_detections(mac)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_le_time ON le_detections(seen_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_le_confidence ON le_detections(confidence)")

    # v8: gov_ssids table (user-managed gov/first-responder SSIDs)
    if "gov_ssids" not in tables:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS gov_ssids ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "ssid TEXT NOT NULL UNIQUE COLLATE NOCASE, "
            "label TEXT NOT NULL DEFAULT '', "
            "category TEXT NOT NULL DEFAULT 'govt', "
            "weight INTEGER NOT NULL DEFAULT 50, "
            "active INTEGER NOT NULL DEFAULT 1, "
            "created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')))"
        )

    # v9: settings table (notification channel config)
    if "settings" not in tables:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS settings ("
            "key TEXT PRIMARY KEY, "
            "value TEXT NOT NULL DEFAULT '', "
            "updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')))"
        )

    conn.commit()


def init_db(conn_or_path) -> sqlite3.Connection:
    """Initialize database schema. Accepts a connection or a path string."""
    if isinstance(conn_or_path, str):
        conn = get_connection(conn_or_path)
    else:
        conn = conn_or_path

    conn.executescript(SCHEMA_SQL)
    _migrate(conn)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Settings helpers (key/value store for notification config)
# ---------------------------------------------------------------------------

def get_setting(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    """Get a single setting value by key."""
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default
    except Exception:
        return default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    """Upsert a setting value."""
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, value),
    )
    conn.commit()


def get_all_settings(conn: sqlite3.Connection) -> dict[str, str]:
    """Get all settings as a {key: value} dict."""
    try:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {r[0]: r[1] for r in rows}
    except Exception:
        return {}
