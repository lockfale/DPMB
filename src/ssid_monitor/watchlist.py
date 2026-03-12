"""Watchlist CRUD operations — add, remove, list, enable, disable SSIDs."""

import sqlite3
from datetime import datetime, timezone


MAX_SSID_BYTES = 32


class WatchlistError(Exception):
    """Base exception for watchlist operations."""
    pass


class SSIDAlreadyExists(WatchlistError):
    pass


class SSIDNotFound(WatchlistError):
    pass


class SSIDTooLong(WatchlistError):
    pass


def _validate_ssid(ssid: str) -> None:
    """Validate SSID is 1-32 bytes per 802.11 spec."""
    encoded = ssid.encode("utf-8")
    if len(encoded) == 0:
        raise WatchlistError("SSID cannot be empty")
    if len(encoded) > MAX_SSID_BYTES:
        raise SSIDTooLong(f"SSID exceeds 32-byte limit ({len(encoded)} bytes)")


def add_ssid(db: sqlite3.Connection, ssid: str) -> None:
    """Add an SSID to the watchlist.

    Raises:
        SSIDTooLong: If SSID exceeds 32 bytes.
        SSIDAlreadyExists: If SSID is already on the watchlist.
    """
    _validate_ssid(ssid)
    try:
        db.execute("INSERT INTO watchlist (ssid) VALUES (?)", (ssid,))
        db.commit()
    except sqlite3.IntegrityError:
        raise SSIDAlreadyExists(f'"{ssid}" already on watchlist.')


def remove_ssid(db: sqlite3.Connection, ssid: str) -> None:
    """Remove an SSID from the watchlist.

    Raises:
        SSIDNotFound: If SSID is not on the watchlist.
    """
    cursor = db.execute("DELETE FROM watchlist WHERE ssid = ?", (ssid,))
    db.commit()
    if cursor.rowcount == 0:
        raise SSIDNotFound(f'"{ssid}" not found on watchlist.')


def list_ssids(db: sqlite3.Connection) -> list[dict]:
    """Return all watchlist entries as list of dicts."""
    rows = db.execute(
        "SELECT ssid, active, created_at FROM watchlist ORDER BY created_at"
    ).fetchall()
    return [dict(row) for row in rows]


def disable_ssid(db: sqlite3.Connection, ssid: str) -> None:
    """Temporarily disable monitoring for an SSID without removing it.

    Raises:
        SSIDNotFound: If SSID is not on the watchlist.
    """
    cursor = db.execute("UPDATE watchlist SET active = 0 WHERE ssid = ?", (ssid,))
    db.commit()
    if cursor.rowcount == 0:
        raise SSIDNotFound(f'"{ssid}" not found on watchlist.')


def enable_ssid(db: sqlite3.Connection, ssid: str) -> None:
    """Re-enable a disabled SSID.

    Raises:
        SSIDNotFound: If SSID is not on the watchlist.
    """
    cursor = db.execute("UPDATE watchlist SET active = 1 WHERE ssid = ?", (ssid,))
    db.commit()
    if cursor.rowcount == 0:
        raise SSIDNotFound(f'"{ssid}" not found on watchlist.')


def get_active_ssids(db: sqlite3.Connection) -> set[str]:
    """Return set of active *alert* SSIDs for watchlist matching.

    Only includes ``watch_type='alert'`` entries — owned SSIDs are excluded
    so your own networks don't trigger detection alerts.
    """
    rows = db.execute(
        "SELECT ssid FROM watchlist WHERE active = 1 AND watch_type = 'alert'"
    ).fetchall()
    return {row["ssid"] for row in rows}
