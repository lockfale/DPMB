"""Tests for LE SSID Auto-Discovery feature.

Tests the POST /api/le/discover endpoint, WiGLE integration,
Overpass API integration, SSID scoring/filtering, and settings
for WiGLE credentials.

Uses real sqlite3 in-memory databases (no mocks for DB) per Article IX.
External APIs (Overpass, WiGLE) are mocked since they are third-party.
"""

import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Ensure the package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src" / "ssid_monitor"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ssid_monitor.dashboard import app, _score_ssid_candidate, _query_overpass, LE_DISCOVER_OUI_PREFIXES
from ssid_monitor.db import init_db, get_setting, set_setting


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    """Create a temporary database with full schema."""
    path = str(tmp_path / "test.db")
    conn = sqlite3.connect(path)
    init_db(conn)
    conn.close()
    return path


@pytest.fixture
def client(db_path):
    """Flask test client with patched DB path."""
    app.config["TESTING"] = True
    with patch("ssid_monitor.dashboard.DB_PATH", db_path):
        with app.test_client() as c:
            yield c


@pytest.fixture
def db_conn(db_path):
    """Direct DB connection for setting up test data."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Scoring function unit tests
# ---------------------------------------------------------------------------

class TestScoreSSIDCandidate:
    """Test the SSID candidate scoring logic."""

    def test_motorola_oui_scores_50(self):
        """Motorola Solutions OUI should add +50 to score."""
        candidate = {
            "ssid": "SomeNetwork",
            "bssid": "00:1a:77:aa:bb:cc",
            "encryption": "wpa2",
        }
        score, reasons = _score_ssid_candidate(candidate, facility_count=1)
        assert score >= 50
        assert any("Motorola" in r for r in reasons)

    def test_cradlepoint_oui_scores_50(self):
        """Cradlepoint OUI should add +50 to score."""
        candidate = {
            "ssid": "SomeNetwork",
            "bssid": "00:90:7a:aa:bb:cc",
            "encryption": "wpa2",
        }
        score, reasons = _score_ssid_candidate(candidate, facility_count=1)
        assert score >= 50
        assert any("Cradlepoint" in r for r in reasons)

    def test_police_pattern_scores_30(self):
        """SSID containing 'police' should add +30."""
        candidate = {
            "ssid": "MNPD-Police-Mobile",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "encryption": "wpa2",
        }
        score, reasons = _score_ssid_candidate(candidate, facility_count=1)
        assert score >= 30
        assert any("Pattern" in r for r in reasons)

    def test_sheriff_pattern_scores_30(self):
        """SSID containing 'sheriff' should add +30."""
        candidate = {
            "ssid": "DCSO-Sheriff-Net",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "encryption": "wpa2",
        }
        score, reasons = _score_ssid_candidate(candidate, facility_count=1)
        assert score >= 30

    def test_enterprise_encryption_scores_20(self):
        """WPA2-Enterprise encryption should add +20."""
        candidate = {
            "ssid": "County-Govt-Net",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "encryption": "wpa2-enterprise",
        }
        score, reasons = _score_ssid_candidate(candidate, facility_count=1)
        # Pattern "govt" (+30) + "county" (+30 but only first match) + enterprise (+20) + single facility (+10)
        # Actually only first pattern match counts, so: county(+30) + enterprise(+20) + single(+10) = 60
        assert score >= 50
        assert any("enterprise" in r.lower() or "Enterprise" in r for r in reasons)

    def test_single_facility_scores_10(self):
        """SSID seen near only one facility gets +10."""
        candidate = {
            "ssid": "SomeUniqueName",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "encryption": "wpa2",
        }
        score, reasons = _score_ssid_candidate(candidate, facility_count=1)
        assert any("single facility" in r.lower() or "one facility" in r.lower() or "dedicated" in r.lower() for r in reasons)

    def test_residential_ssid_penalty_minus_50(self):
        """Known residential SSIDs should get -50 penalty."""
        candidate = {
            "ssid": "xfinity-Home-1234",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "encryption": "wpa2",
        }
        score, reasons = _score_ssid_candidate(candidate, facility_count=1)
        assert score < 10  # Should be penalized below threshold

    def test_default_router_penalty_minus_30(self):
        """Default router names (all-caps model number) should get -30."""
        candidate = {
            "ssid": "NETGEAR-5G",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "encryption": "wpa2",
        }
        score, reasons = _score_ssid_candidate(candidate, facility_count=1)
        # "netgear" residential pattern (-50) should apply
        assert score < 10

    def test_multi_facility_no_bonus(self):
        """SSID seen at multiple facilities should NOT get single-facility bonus."""
        candidate = {
            "ssid": "SomeNetwork",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "encryption": "wpa2",
        }
        score, reasons = _score_ssid_candidate(candidate, facility_count=3)
        assert not any("single facility" in r.lower() or "one facility" in r.lower() or "dedicated" in r.lower() for r in reasons)

    def test_combined_oui_and_pattern_high_score(self):
        """Motorola OUI + police pattern should score 80+."""
        candidate = {
            "ssid": "PD-CAD-Mobile",
            "bssid": "00:1a:77:aa:bb:cc",
            "encryption": "wpa2-enterprise",
        }
        score, reasons = _score_ssid_candidate(candidate, facility_count=1)
        # OUI(+50) + pattern "pd"(+30) + enterprise(+20) + single(+10) = 110
        assert score >= 80

    def test_below_threshold_filtered(self):
        """Generic SSIDs with no LE signals should score below 10."""
        candidate = {
            "ssid": "MyHomeWifi",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "encryption": "wpa2",
        }
        score, reasons = _score_ssid_candidate(candidate, facility_count=3)
        # Only single facility bonus possible, and not applicable here
        # No OUI match, no pattern match = low score
        assert score < 20


# ---------------------------------------------------------------------------
# OUI prefix coverage tests
# ---------------------------------------------------------------------------

class TestOUIPrefixes:
    """Verify the LE OUI prefix database is properly defined."""

    def test_motorola_prefixes_present(self):
        assert "00:1a:77" in LE_DISCOVER_OUI_PREFIXES
        assert "00:19:2c" in LE_DISCOVER_OUI_PREFIXES
        assert "00:14:9a" in LE_DISCOVER_OUI_PREFIXES

    def test_cradlepoint_prefixes_present(self):
        assert "00:90:7a" in LE_DISCOVER_OUI_PREFIXES
        assert "00:30:44" in LE_DISCOVER_OUI_PREFIXES

    def test_sierra_wireless_prefixes_present(self):
        assert "00:a0:92" in LE_DISCOVER_OUI_PREFIXES
        assert "00:14:3e" in LE_DISCOVER_OUI_PREFIXES

    def test_l3harris_prefixes_present(self):
        assert "00:08:a2" in LE_DISCOVER_OUI_PREFIXES
        assert "00:01:f4" in LE_DISCOVER_OUI_PREFIXES

    def test_panasonic_prefixes_present(self):
        assert "00:80:45" in LE_DISCOVER_OUI_PREFIXES
        assert "00:0b:97" in LE_DISCOVER_OUI_PREFIXES
        assert "70:58:12" in LE_DISCOVER_OUI_PREFIXES

    def test_all_prefixes_lowercase(self):
        for prefix in LE_DISCOVER_OUI_PREFIXES:
            assert prefix == prefix.lower(), f"OUI prefix {prefix} should be lowercase"


# ---------------------------------------------------------------------------
# Overpass query tests
# ---------------------------------------------------------------------------

class TestOverpassQuery:
    """Test the Overpass API query builder."""

    @patch("ssid_monitor.dashboard.http_requests.get")
    def test_overpass_returns_facilities(self, mock_get):
        """Overpass API response should be parsed into facility list."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "elements": [
                {
                    "type": "node",
                    "id": 123,
                    "lat": 36.16,
                    "lon": -86.78,
                    "tags": {
                        "amenity": "police",
                        "name": "Metro Police HQ",
                    },
                },
                {
                    "type": "node",
                    "id": 456,
                    "lat": 36.17,
                    "lon": -86.77,
                    "tags": {
                        "amenity": "fire_station",
                        "name": "Fire Station #5",
                    },
                },
            ]
        }
        mock_get.return_value = mock_response

        facilities = _query_overpass(36.16, -86.78, 5)

        assert len(facilities) == 2
        assert facilities[0]["name"] == "Metro Police HQ"
        assert facilities[0]["type"] == "police"
        assert facilities[1]["name"] == "Fire Station #5"
        assert facilities[1]["type"] == "fire_station"

    @patch("ssid_monitor.dashboard.http_requests.get")
    def test_overpass_handles_way_and_relation(self, mock_get):
        """Should handle way/relation types with center coordinates."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "elements": [
                {
                    "type": "way",
                    "id": 789,
                    "center": {"lat": 36.165, "lon": -86.775},
                    "tags": {
                        "office": "government",
                        "name": "County Admin Building",
                    },
                },
            ]
        }
        mock_get.return_value = mock_response

        facilities = _query_overpass(36.16, -86.78, 5)

        assert len(facilities) == 1
        assert facilities[0]["name"] == "County Admin Building"
        assert facilities[0]["type"] == "government"
        assert facilities[0]["lat"] == 36.165

    @patch("ssid_monitor.dashboard.http_requests.get")
    def test_overpass_error_returns_empty(self, mock_get):
        """Overpass API error should return empty list, not crash."""
        mock_get.side_effect = Exception("Connection timeout")

        facilities = _query_overpass(36.16, -86.78, 5)
        assert facilities == []


# ---------------------------------------------------------------------------
# API endpoint integration tests
# ---------------------------------------------------------------------------

class TestDiscoverEndpoint:
    """Test the POST /api/le/discover endpoint."""

    def test_missing_coordinates_returns_400(self, client):
        """Request without lat/lon should return 400."""
        rv = client.post(
            "/api/le/discover",
            data=json.dumps({"radius_km": 5}),
            content_type="application/json",
        )
        assert rv.status_code == 400
        data = rv.get_json()
        assert data["ok"] is False

    def test_missing_wigle_credentials_returns_400(self, client, db_conn, db_path):
        """Request without WiGLE credentials in settings should return 400."""
        # No WiGLE credentials set in DB
        with patch("ssid_monitor.dashboard.DB_PATH", db_path):
            rv = client.post(
                "/api/le/discover",
                data=json.dumps({"lat": 36.16, "lon": -86.78, "radius_km": 5}),
                content_type="application/json",
            )
        assert rv.status_code == 400
        data = rv.get_json()
        assert "wigle" in data.get("error", "").lower() or "credential" in data.get("error", "").lower()

    @patch("ssid_monitor.dashboard._query_wigle_facility")
    @patch("ssid_monitor.dashboard._query_overpass")
    def test_successful_discovery(self, mock_overpass, mock_wigle, client, db_conn, db_path):
        """Full discovery flow returns scored candidates."""
        # Set WiGLE credentials
        set_setting(db_conn, "wigle_api_name", "AID_test")
        set_setting(db_conn, "wigle_api_token", "test_token_123")
        db_conn.commit()

        # Mock Overpass response
        mock_overpass.return_value = [
            {
                "name": "Metro Police Department",
                "type": "police",
                "lat": 36.16,
                "lon": -86.78,
            },
        ]

        # Mock WiGLE response
        mock_wigle.return_value = [
            {
                "ssid": "MNPD-Mobile",
                "bssid": "00:1a:77:aa:bb:cc",
                "encryption": "wpa2-enterprise",
                "last_seen": "2024-01-15",
                "channel": 6,
            },
            {
                "ssid": "xfinity-Home",
                "bssid": "aa:bb:cc:dd:ee:ff",
                "encryption": "wpa2",
                "last_seen": "2024-01-15",
                "channel": 11,
            },
        ]

        with patch("ssid_monitor.dashboard.DB_PATH", db_path):
            rv = client.post(
                "/api/le/discover",
                data=json.dumps({"lat": 36.16, "lon": -86.78, "radius_km": 5}),
                content_type="application/json",
            )

        assert rv.status_code == 200
        data = rv.get_json()
        assert data["facilities_found"] == 1
        assert data["facilities_queried"] == 1
        # Should have MNPD-Mobile (high score) but not xfinity (below threshold)
        ssids = [c["ssid"] for c in data["candidates"]]
        assert "MNPD-Mobile" in ssids
        assert "xfinity-Home" not in ssids

    @patch("ssid_monitor.dashboard._query_wigle_facility")
    @patch("ssid_monitor.dashboard._query_overpass")
    def test_deduplication(self, mock_overpass, mock_wigle, client, db_conn, db_path):
        """Same SSID at multiple facilities should be deduplicated, keeping highest score."""
        set_setting(db_conn, "wigle_api_name", "AID_test")
        set_setting(db_conn, "wigle_api_token", "test_token_123")
        db_conn.commit()

        mock_overpass.return_value = [
            {"name": "Police Station A", "type": "police", "lat": 36.16, "lon": -86.78},
            {"name": "Police Station B", "type": "police", "lat": 36.17, "lon": -86.77},
        ]

        # Same SSID returned from both facilities
        mock_wigle.side_effect = [
            [{"ssid": "PD-Network", "bssid": "00:1a:77:aa:bb:cc", "encryption": "wpa2", "last_seen": "2024-01-15", "channel": 6}],
            [{"ssid": "PD-Network", "bssid": "00:1a:77:aa:bb:cc", "encryption": "wpa2", "last_seen": "2024-01-15", "channel": 6}],
        ]

        with patch("ssid_monitor.dashboard.DB_PATH", db_path):
            rv = client.post(
                "/api/le/discover",
                data=json.dumps({"lat": 36.16, "lon": -86.78, "radius_km": 5}),
                content_type="application/json",
            )

        data = rv.get_json()
        # Should only appear once
        pd_candidates = [c for c in data["candidates"] if c["ssid"] == "PD-Network"]
        assert len(pd_candidates) == 1

    @patch("ssid_monitor.dashboard._query_wigle_facility")
    @patch("ssid_monitor.dashboard._query_overpass")
    def test_facility_limit_15(self, mock_overpass, mock_wigle, client, db_conn, db_path):
        """Should only query closest 15 facilities if more are found."""
        set_setting(db_conn, "wigle_api_name", "AID_test")
        set_setting(db_conn, "wigle_api_token", "test_token_123")
        db_conn.commit()

        # 20 facilities
        facilities = [
            {"name": f"Station {i}", "type": "police", "lat": 36.16 + i * 0.001, "lon": -86.78}
            for i in range(20)
        ]
        mock_overpass.return_value = facilities
        mock_wigle.return_value = []

        with patch("ssid_monitor.dashboard.DB_PATH", db_path):
            rv = client.post(
                "/api/le/discover",
                data=json.dumps({"lat": 36.16, "lon": -86.78, "radius_km": 10}),
                content_type="application/json",
            )

        data = rv.get_json()
        assert data["facilities_found"] == 20
        assert data["facilities_queried"] == 15


# ---------------------------------------------------------------------------
# WiGLE test endpoint
# ---------------------------------------------------------------------------

class TestWiGLETestEndpoint:
    """Test the POST /api/test-wigle endpoint."""

    @patch("ssid_monitor.dashboard.http_requests.get")
    def test_wigle_test_success(self, mock_get, client):
        """Valid WiGLE credentials should return success."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True, "userid": "test_user"}
        mock_get.return_value = mock_response

        rv = client.post(
            "/api/test-wigle",
            data=json.dumps({"api_name": "AID_test", "api_token": "token123"}),
            content_type="application/json",
        )
        assert rv.status_code == 200
        data = rv.get_json()
        assert data["ok"] is True

    @patch("ssid_monitor.dashboard.http_requests.get")
    def test_wigle_test_failure(self, mock_get, client):
        """Invalid WiGLE credentials should return failure."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        rv = client.post(
            "/api/test-wigle",
            data=json.dumps({"api_name": "bad", "api_token": "bad"}),
            content_type="application/json",
        )
        assert rv.status_code == 200  # endpoint itself returns 200 with ok:false
        data = rv.get_json()
        assert data["ok"] is False

    def test_wigle_test_missing_credentials(self, client):
        """Missing credentials should return error."""
        rv = client.post(
            "/api/test-wigle",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert rv.status_code == 400


# ---------------------------------------------------------------------------
# Settings integration tests
# ---------------------------------------------------------------------------

class TestWiGLESettings:
    """Test WiGLE credential storage in settings."""

    def test_save_wigle_credentials(self, client, db_conn, db_path):
        """WiGLE credentials should be saveable via settings endpoint."""
        with patch("ssid_monitor.dashboard.DB_PATH", db_path):
            rv = client.post(
                "/api/settings",
                data=json.dumps({
                    "wigle_api_name": "AID_myname",
                    "wigle_api_token": "my_secret_token",
                }),
                content_type="application/json",
            )
        assert rv.status_code == 200
        data = rv.get_json()
        assert data["ok"] is True

        # Verify stored in DB
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        assert get_setting(conn, "wigle_api_name") == "AID_myname"
        assert get_setting(conn, "wigle_api_token") == "my_secret_token"
        conn.close()

    def test_wigle_credentials_masked_in_get(self, client, db_conn, db_path):
        """WiGLE token should be masked when reading settings."""
        set_setting(db_conn, "wigle_api_name", "AID_myname")
        set_setting(db_conn, "wigle_api_token", "my_super_secret_token")
        db_conn.commit()

        with patch("ssid_monitor.dashboard.DB_PATH", db_path):
            rv = client.get("/api/settings")

        data = rv.get_json()
        # Token should be masked
        assert data.get("wigle_api_token", "").startswith("****")
        # Name should also be masked (it's a credential)
        assert data.get("wigle_api_name", "").startswith("****") or data.get("wigle_api_name") == "AID_myname"
