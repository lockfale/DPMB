"""SSID matching for captured 802.11 probe request frames."""

import logging

logger = logging.getLogger(__name__)


def match_probes(probes: list, active_ssids: set[str]) -> list:
    """Return probe request frames whose SSID appears in the active watchlist.

    Matching is case-sensitive per IEEE 802.11 specification — SSIDs are
    arbitrary octet strings and two SSIDs differing only in case are
    distinct networks.

    Args:
        probes: List of ProbeFrame namedtuples captured from the air.
        active_ssids: Set of SSID strings currently on the watchlist.

    Returns:
        List of ProbeFrame objects that matched an active SSID.
    """
    if not active_ssids:
        logger.debug("active_ssids is empty — skipping match pass")
        return []

    matches = [
        probe
        for probe in probes
        if probe.ssid and probe.ssid in active_ssids
    ]

    logger.debug(
        "match_probes: checked %d probes, found %d matches",
        len(probes),
        len(matches),
    )

    return matches
