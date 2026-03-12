"""Tests for le_detector.py -- multi-signal LE scoring engine.

Uses real sqlite3 in-memory databases (no mocks) per Article IX.
"""

import sqlite3
import sys
import time
import threading
from collections import namedtuple
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure the package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import init_db, get_connection
from le_detector import (
    LEDetector,
    LEEvent,
    LE_OUI_DB,
    LE_SSID_PATTERNS,
    OUIEntry,
    SSIDPattern,
    TrajectoryState,
    RSSIReading,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH,
    CONFIDENCE_CRITICAL,
    _score_to_confidence,
    get_detector,
    reset_detector,
)

# Re-use scanner frame types for integration tests
BeaconFrame = namedtuple("BeaconFrame", ["bssid", "ssid", "channel", "rssi", "encryption", "is_probe_resp"])
ProbeFrame = namedtuple("ProbeFrame", ["ssid", "device_mac", "rssi", "channel"])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    """Create a temporary database with full schema."""
    path = str(tmp_path / "test.db")
    conn = init_db(path)
    conn.close()
    return path


@pytest.fixture
def detector(db_path):
    """Create a fresh LEDetector with a real database."""
    return LEDetector(db_path)


@pytest.fixture
def db(db_path):
    """Get a database connection for assertions."""
    return get_connection(db_path)


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Reset the module singleton between tests."""
    reset_detector()
    yield
    reset_detector()


# ---------------------------------------------------------------------------
# Data integrity: OUI and SSID tables
# ---------------------------------------------------------------------------

class TestOUIDatabase:
    """Verify the OUI database is well-formed."""

    def test_all_ouis_are_lowercase_8_chars(self):
        for oui, entry in LE_OUI_DB.items():
            assert oui == oui.lower(), f"OUI {oui} not lowercase"
            assert len(oui) == 8, f"OUI {oui} wrong length (expected xx:xx:xx)"
            assert oui[2] == ":" and oui[5] == ":", f"OUI {oui} bad format"

    def test_all_entries_have_positive_weights(self):
        for oui, entry in LE_OUI_DB.items():
            assert entry.weight > 0, f"OUI {oui} has non-positive weight"
            assert entry.vendor, f"OUI {oui} missing vendor name"

    def test_cradlepoint_is_high_weight(self):
        cradlepoint_ouis = {k: v for k, v in LE_OUI_DB.items() if "Cradlepoint" in v.vendor}
        assert len(cradlepoint_ouis) >= 4, "Should have multiple Cradlepoint OUIs"
        for oui, entry in cradlepoint_ouis.items():
            assert entry.weight >= 40, f"Cradlepoint OUI {oui} should be high weight"

    def test_panasonic_is_medium_weight(self):
        panasonic_ouis = {k: v for k, v in LE_OUI_DB.items() if "Panasonic" in v.vendor}
        assert len(panasonic_ouis) >= 3
        for oui, entry in panasonic_ouis.items():
            assert entry.weight == 20, f"Panasonic OUI {oui} should be medium weight"

    def test_cellebrite_is_critical_weight(self):
        cellebrite_ouis = {k: v for k, v in LE_OUI_DB.items() if "Cellebrite" in v.vendor}
        assert len(cellebrite_ouis) >= 1
        for oui, entry in cellebrite_ouis.items():
            assert entry.weight >= 50, f"Cellebrite OUI {oui} should be critical weight"

    def test_motorola_solutions_is_high_weight(self):
        moto_ouis = {k: v for k, v in LE_OUI_DB.items() if "Motorola Solutions" in v.vendor}
        assert len(moto_ouis) >= 5
        for oui, entry in moto_ouis.items():
            assert entry.weight >= 40

    def test_l3harris_is_high_weight(self):
        harris_ouis = {k: v for k, v in LE_OUI_DB.items() if "L3Harris" in v.vendor}
        assert len(harris_ouis) >= 2
        for oui, entry in harris_ouis.items():
            assert entry.weight >= 40


class TestSSIDPatterns:
    """Verify the SSID pattern database is well-formed and matches expected strings."""

    def test_all_patterns_compile(self):
        for p in LE_SSID_PATTERNS:
            assert isinstance(p.regex, type(LE_SSID_PATTERNS[0].regex))
            assert p.weight > 0
            assert p.label

    def test_police_patterns_match(self):
        test_ssids = ["POLICE-NET", "PD-UNIT5", "SHERIFF-MOBILE", "LAPD"]
        for ssid in test_ssids:
            matched = any(p.regex.search(ssid) for p in LE_SSID_PATTERNS)
            assert matched, f"SSID '{ssid}' should match an LE pattern"

    def test_federal_patterns_match(self):
        test_ssids = ["FBI-MOBILE", "DEA-FIELD", "ATF-OPS", "DHS-NET"]
        for ssid in test_ssids:
            matched = any(p.regex.search(ssid) for p in LE_SSID_PATTERNS)
            assert matched, f"SSID '{ssid}' should match an LE pattern"

    def test_fleet_patterns_match(self):
        test_ssids = ["CRADLEPOINT-IBR", "CP-IBR900-FLEET", "NETCLOUD-001"]
        for ssid in test_ssids:
            matched = any(p.regex.search(ssid) for p in LE_SSID_PATTERNS)
            assert matched, f"SSID '{ssid}' should match an LE pattern"

    def test_benign_ssids_do_not_match(self):
        test_ssids = ["HomeWiFi", "Starbucks", "xfinitywifi", "ATT-Guest", "NETGEAR42"]
        for ssid in test_ssids:
            matched = any(p.regex.search(ssid) for p in LE_SSID_PATTERNS)
            assert not matched, f"SSID '{ssid}' should NOT match an LE pattern"

    def test_case_insensitive(self):
        test_ssids = ["police-net", "Police-NET", "POLICE-NET", "Sheriff-Mobile"]
        for ssid in test_ssids:
            matched = any(p.regex.search(ssid) for p in LE_SSID_PATTERNS)
            assert matched, f"SSID '{ssid}' should match case-insensitively"


# ---------------------------------------------------------------------------
# Score-to-confidence mapping
# ---------------------------------------------------------------------------

class TestScoreToConfidence:

    def test_zero_score_is_none(self):
        assert _score_to_confidence(0) == "none"

    def test_low_threshold(self):
        assert _score_to_confidence(CONFIDENCE_LOW) == "low"
        assert _score_to_confidence(CONFIDENCE_LOW - 1) == "none"

    def test_medium_threshold(self):
        assert _score_to_confidence(CONFIDENCE_MEDIUM) == "medium"

    def test_high_threshold(self):
        assert _score_to_confidence(CONFIDENCE_HIGH) == "high"

    def test_critical_threshold(self):
        assert _score_to_confidence(CONFIDENCE_CRITICAL) == "critical"
        assert _score_to_confidence(150) == "critical"


# ---------------------------------------------------------------------------
# Signal trajectory tracker
# ---------------------------------------------------------------------------

class TestTrajectoryState:

    def test_unknown_with_few_readings(self):
        ts = TrajectoryState()
        ts.add_reading(-70)
        assert ts.trend == "unknown"
        ts.add_reading(-65)
        assert ts.trend == "unknown"  # still only 2 readings

    def test_approaching_detection(self):
        ts = TrajectoryState()
        for rssi in [-80, -75, -70, -65, -58]:
            ts.add_reading(rssi)
        assert ts.trend == "approaching"
        assert ts.trend_delta > 0

    def test_departing_detection(self):
        ts = TrajectoryState()
        for rssi in [-50, -55, -62, -70, -78]:
            ts.add_reading(rssi)
        assert ts.trend == "departing"
        assert ts.trend_delta < 0

    def test_stable_detection(self):
        ts = TrajectoryState()
        for rssi in [-65, -66, -64, -65, -66]:
            ts.add_reading(rssi)
        assert ts.trend == "stable"

    def test_max_readings_enforced(self):
        ts = TrajectoryState()
        for i in range(50):
            ts.add_reading(-70 + i % 5)
        assert len(ts.readings) <= TrajectoryState.MAX_READINGS


# ---------------------------------------------------------------------------
# OUI scoring
# ---------------------------------------------------------------------------

class TestOUIScoring:

    def test_cradlepoint_oui_returns_high_score(self, detector):
        score, ind = detector._score_oui("00:0c:e6:ab:cd:ef")
        assert score >= 40
        assert ind is not None
        assert "Cradlepoint" in ind

    def test_panasonic_oui_returns_medium_score(self, detector):
        score, ind = detector._score_oui("00:07:f6:11:22:33")
        assert score == 20
        assert "Panasonic" in ind

    def test_unknown_oui_returns_zero(self, detector):
        score, ind = detector._score_oui("aa:bb:cc:dd:ee:ff")
        assert score == 0
        assert ind is None

    def test_empty_mac_returns_zero(self, detector):
        score, ind = detector._score_oui("")
        assert score == 0

    def test_short_mac_returns_zero(self, detector):
        score, ind = detector._score_oui("00:0c")
        assert score == 0


# ---------------------------------------------------------------------------
# SSID scoring
# ---------------------------------------------------------------------------

class TestSSIDScoring:

    def test_police_ssid_high_score(self, detector):
        score, inds = detector._score_ssid("POLICE-NET-5")
        assert score >= 35
        assert len(inds) > 0

    def test_mdt_ssid_medium_score(self, detector):
        score, inds = detector._score_ssid("MDT-42-MOBILE")
        assert score >= 30

    def test_government_ssid_low_score(self, detector):
        score, inds = detector._score_ssid("GOV-WIFI")
        assert score >= 10
        assert score < 30

    def test_benign_ssid_zero_score(self, detector):
        score, inds = detector._score_ssid("MyHomeNetwork")
        assert score == 0
        assert inds == []

    def test_empty_ssid_zero_score(self, detector):
        score, inds = detector._score_ssid("")
        assert score == 0


# ---------------------------------------------------------------------------
# Full scoring pipeline (check_beacon / check_probe)
# ---------------------------------------------------------------------------

class TestCheckBeacon:

    def test_cradlepoint_beacon_with_le_ssid_returns_high(self, detector):
        """Cradlepoint OUI + LE SSID = high/critical confidence."""
        event = detector.check_beacon(
            bssid="00:0c:e6:ab:cd:ef",
            ssid="PD-UNIT3",
            rssi=-55,
            channel=6,
        )
        assert event is not None
        assert event.confidence in ("high", "critical")
        assert event.score >= CONFIDENCE_HIGH
        assert len(event.indicators) >= 2

    def test_new_ap_with_le_oui_gets_bonus(self, detector, db):
        """A brand-new BSSID with LE OUI should get the new-AP bonus."""
        # Make sure there's no existing AP entry
        row = db.execute(
            "SELECT bssid FROM access_points WHERE bssid = '00:0c:e6:aa:bb:cc'"
        ).fetchone()
        assert row is None

        event = detector.check_beacon(
            bssid="00:0c:e6:aa:bb:cc",
            ssid="NETCLOUD-FLEET",
            rssi=-60,
            channel=1,
        )
        assert event is not None
        assert event.is_new_ap
        assert any("New AP" in i for i in event.indicators)

    def test_benign_beacon_returns_none(self, detector):
        event = detector.check_beacon(
            bssid="aa:bb:cc:dd:ee:ff",
            ssid="Starbucks-WiFi",
            rssi=-70,
            channel=6,
        )
        assert event is None

    def test_event_persisted_to_database(self, detector, db):
        """Events should be written to security_events table."""
        detector.check_beacon(
            bssid="00:0c:e6:ab:cd:ef",
            ssid="POLICE-NET",
            rssi=-55,
            channel=6,
        )
        rows = db.execute(
            "SELECT * FROM security_events WHERE event_type = 'le_signature'"
        ).fetchall()
        assert len(rows) >= 1
        row = rows[0]
        assert row["device_mac"] == "00:0c:e6:ab:cd:ef"
        assert row["ssid"] == "POLICE-NET"
        assert "conf=" in row["detail"]


class TestCheckProbe:

    def test_le_oui_probe_returns_event(self, detector):
        event = detector.check_probe(
            device_mac="00:04:56:11:22:33",  # Motorola Solutions
            ssid="MDT-5",
            rssi=-60,
            channel=11,
        )
        assert event is not None
        assert event.confidence in ("medium", "high", "critical")

    def test_panasonic_only_returns_low_or_medium(self, detector):
        """Panasonic alone (no SSID match) should be low confidence."""
        event = detector.check_probe(
            device_mac="00:07:f6:11:22:33",  # Panasonic
            ssid="HomeWiFi",  # benign SSID
            rssi=-65,
            channel=1,
        )
        assert event is not None
        assert event.confidence == "low"

    def test_benign_probe_returns_none(self, detector):
        event = detector.check_probe(
            device_mac="aa:bb:cc:dd:ee:ff",
            ssid="MyNetwork",
            rssi=-70,
            channel=6,
        )
        assert event is None

    def test_ssid_only_match_returns_event(self, detector):
        """Strong SSID match alone should trigger detection."""
        event = detector.check_probe(
            device_mac="aa:bb:cc:dd:ee:ff",  # unknown OUI
            ssid="SWAT-MOBILE",
            rssi=-50,
            channel=6,
        )
        assert event is not None
        assert event.score >= CONFIDENCE_MEDIUM


# ---------------------------------------------------------------------------
# Cooldown / deduplication
# ---------------------------------------------------------------------------

class TestCooldown:

    def test_cooldown_prevents_duplicate_notification(self, detector):
        """Second detection within 15 min should still return event but not re-notify."""
        with patch("le_detector.LEDetector._notify_event") as mock_notify:
            ev1 = detector.check_beacon(
                bssid="00:0c:e6:ab:cd:ef", ssid="POLICE-NET",
                rssi=-55, channel=6,
            )
            ev2 = detector.check_beacon(
                bssid="00:0c:e6:ab:cd:ef", ssid="POLICE-NET",
                rssi=-50, channel=6,
            )
            # Both should return events
            assert ev1 is not None
            assert ev2 is not None
            # But notify should only be called once
            assert mock_notify.call_count == 1

    def test_different_macs_not_affected_by_cooldown(self, detector):
        with patch("le_detector.LEDetector._notify_event") as mock_notify:
            detector.check_beacon(
                bssid="00:0c:e6:ab:cd:ef", ssid="POLICE-NET",
                rssi=-55, channel=6,
            )
            detector.check_beacon(
                bssid="00:0c:e6:11:22:33", ssid="POLICE-NET",
                rssi=-55, channel=6,
            )
            assert mock_notify.call_count == 2


# ---------------------------------------------------------------------------
# Signal trajectory integration
# ---------------------------------------------------------------------------

class TestTrajectoryIntegration:

    def test_approaching_signal_adds_bonus(self, detector):
        """Simulating a vehicle approach should add trajectory bonus."""
        events = []
        for rssi in [-80, -75, -68, -60, -52]:
            ev = detector.check_beacon(
                bssid="00:0c:e6:ab:cd:ef", ssid="CRADLEPOINT",
                rssi=rssi, channel=6,
            )
            if ev:
                events.append(ev)

        # The later events should have higher scores due to trajectory
        assert len(events) >= 3
        last = events[-1]
        assert last.trend == "approaching"
        # Should have trajectory indicator
        assert any("Trajectory" in i or "approaching" in i for i in last.indicators)

    def test_get_trajectory_returns_data(self, detector):
        """After checking beacons, trajectory data should be queryable."""
        for rssi in [-70, -65, -60]:
            detector.check_beacon(
                bssid="00:0c:e6:ab:cd:ef", ssid="PD-NET",
                rssi=rssi, channel=1,
            )
        traj = detector.get_trajectory("00:0c:e6:ab:cd:ef")
        assert traj is not None
        assert traj["reading_count"] == 3
        assert traj["last_rssi"] == -60


# ---------------------------------------------------------------------------
# Channel correlation
# ---------------------------------------------------------------------------

class TestChannelCorrelation:

    def test_multiple_le_on_same_channel_adds_bonus(self, detector):
        """Two different LE entities on the same channel should correlate."""
        # First LE entity
        detector.check_beacon(
            bssid="00:0c:e6:11:11:11", ssid="PD-NET",
            rssi=-55, channel=6,
        )
        # Second LE entity on same channel
        ev2 = detector.check_beacon(
            bssid="00:04:56:22:22:22", ssid="MDT-3",
            rssi=-60, channel=6,
        )
        assert ev2 is not None
        assert any("Channel correlation" in i for i in ev2.indicators)


# ---------------------------------------------------------------------------
# Batch processing (process_beacons / process_probes)
# ---------------------------------------------------------------------------

class TestBatchProcessing:

    def test_process_beacons_batch(self, detector):
        beacons = [
            BeaconFrame("00:0c:e6:aa:bb:cc", "PD-NET", 6, -55, "WPA2/WPA3", False),
            BeaconFrame("aa:bb:cc:dd:ee:ff", "HomeWiFi", 1, -70, "WPA2/WPA3", False),
            BeaconFrame("00:04:56:11:22:33", "DISPATCH", 11, -60, "WPA2/WPA3", False),
        ]
        events = detector.process_beacons(beacons)
        # Should detect LE on first and third, skip the benign one
        assert len(events) >= 2
        macs = {e.mac for e in events}
        assert "00:0c:e6:aa:bb:cc" in macs
        assert "00:04:56:11:22:33" in macs
        assert "aa:bb:cc:dd:ee:ff" not in macs

    def test_process_probes_batch(self, detector):
        probes = [
            ProbeFrame("SHERIFF-NET", "00:04:56:11:22:33", -55, 6),
            ProbeFrame("MyWiFi", "aa:bb:cc:dd:ee:ff", -70, 1),
        ]
        events = detector.process_probes(probes)
        assert len(events) >= 1
        assert events[0].mac == "00:04:56:11:22:33"


# ---------------------------------------------------------------------------
# Dashboard API (get_le_activity / get_le_summary)
# ---------------------------------------------------------------------------

class TestDashboardAPI:

    def test_get_le_activity_returns_recent_events(self, detector):
        detector.check_beacon(
            bssid="00:0c:e6:ab:cd:ef", ssid="POLICE-NET",
            rssi=-55, channel=6,
        )
        activity = detector.get_le_activity(minutes=5)
        assert len(activity) >= 1
        ev = activity[0]
        assert ev["mac"] == "00:0c:e6:ab:cd:ef"
        assert ev["ssid"] == "POLICE-NET"
        assert ev["confidence"] in ("low", "medium", "high", "critical")
        assert ev["score"] > 0

    def test_get_le_activity_empty_when_no_events(self, detector):
        activity = detector.get_le_activity(minutes=5)
        assert activity == []

    def test_get_le_summary_counts(self, detector):
        # Generate multiple events
        for mac_suffix in ["11", "22", "33"]:
            detector.check_beacon(
                bssid=f"00:0c:e6:ab:cd:{mac_suffix}",
                ssid="POLICE-NET",
                rssi=-55,
                channel=6,
            )
        summary = detector.get_le_summary(minutes=5)
        assert summary["total_events"] >= 3
        assert summary["unique_macs"] >= 3


# ---------------------------------------------------------------------------
# Cleanup / maintenance
# ---------------------------------------------------------------------------

class TestCleanup:

    def test_cleanup_stale_state(self, detector):
        """Entries older than max_age_sec should be purged."""
        # Add a trajectory entry
        detector.check_beacon(
            bssid="00:0c:e6:ab:cd:ef", ssid="PD-NET",
            rssi=-55, channel=6,
        )
        assert "00:0c:e6:ab:cd:ef" in detector._trajectories

        # Manually age the readings
        traj = detector._trajectories["00:0c:e6:ab:cd:ef"]
        for r in traj.readings:
            r.timestamp = time.monotonic() - 7200  # 2 hours ago

        purged = detector.cleanup_stale_state(max_age_sec=3600)
        assert purged >= 1
        assert "00:0c:e6:ab:cd:ef" not in detector._trajectories


# ---------------------------------------------------------------------------
# Singleton / module-level API
# ---------------------------------------------------------------------------

class TestSingleton:

    def test_get_detector_requires_db_path_first(self):
        reset_detector()
        with pytest.raises(RuntimeError, match="not initialized"):
            get_detector()

    def test_get_detector_creates_and_reuses(self, db_path):
        d1 = get_detector(db_path)
        d2 = get_detector()
        assert d1 is d2

    def test_reset_detector_clears_singleton(self, db_path):
        d1 = get_detector(db_path)
        reset_detector()
        d2 = get_detector(db_path)
        assert d1 is not d2


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestThreadSafety:

    def test_concurrent_checks_no_crash(self, detector):
        """Multiple threads calling check_beacon simultaneously should not crash."""
        errors = []

        def worker(mac_id):
            try:
                for i in range(10):
                    detector.check_beacon(
                        bssid=f"00:0c:e6:{mac_id:02x}:{i:02x}:ff",
                        ssid="POLICE-NET",
                        rssi=-55 + i,
                        channel=6,
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Thread errors: {errors}"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_none_ssid_handled(self, detector):
        """None SSID should not crash."""
        event = detector.check_beacon(
            bssid="00:0c:e6:ab:cd:ef", ssid=None,
            rssi=-55, channel=6,
        )
        # Should still trigger on OUI alone
        assert event is not None

    def test_empty_string_mac(self, detector):
        event = detector.check_probe(
            device_mac="", ssid="POLICE-NET", rssi=-55, channel=6,
        )
        # Should still match on SSID
        assert event is not None

    def test_very_low_rssi(self, detector):
        """Extremely weak signal should still be scored."""
        event = detector.check_beacon(
            bssid="00:0c:e6:ab:cd:ef", ssid="CRADLEPOINT-NET",
            rssi=-95, channel=1,
        )
        assert event is not None

    def test_none_channel(self, detector):
        """None channel should be handled gracefully."""
        event = detector.check_beacon(
            bssid="00:0c:e6:ab:cd:ef", ssid="PD-MOBILE",
            rssi=-55, channel=None,
        )
        assert event is not None
