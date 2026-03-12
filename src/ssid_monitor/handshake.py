"""WPA handshake capture — passive EAPOL collection, hc22000 output for hashcat."""

import logging
import struct
import time
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)

HANDSHAKE_DIR = "/var/lib/dpmb/handshakes"


def parse_eapol_key(raw_eapol: bytes) -> dict | None:
    """Parse EAPOL-Key frame fields from raw EAPOL bytes.

    Byte layout (from EAPOL header):
        0:      Version
        1:      Type (3 = Key)
        2-3:    Body Length
        4:      Descriptor Type
        5-6:    Key Information
        7-8:    Key Length
        9-16:   Replay Counter
        17-48:  Key Nonce (32 bytes)
        49-64:  Key IV
        65-72:  Key RSC
        73-80:  Reserved
        81-96:  Key MIC (16 bytes)
        97-98:  Key Data Length
        99+:    Key Data
    """
    if len(raw_eapol) < 99:
        return None

    if raw_eapol[1] != 3:  # Not EAPOL-Key
        return None

    key_info = struct.unpack(">H", raw_eapol[5:7])[0]
    replay_counter = raw_eapol[9:17]
    nonce = raw_eapol[17:49]
    mic = raw_eapol[81:97]

    # Key info flags
    has_ack = bool(key_info & 0x0080)
    has_mic = bool(key_info & 0x0100)
    has_secure = bool(key_info & 0x0200)
    has_install = bool(key_info & 0x0040)

    # Determine 4-way handshake message number
    if has_ack and not has_mic:
        msg_num = 1   # AP -> STA: ANonce, no MIC
    elif not has_ack and has_mic and not has_secure:
        msg_num = 2   # STA -> AP: SNonce + MIC
    elif has_ack and has_mic and has_install:
        msg_num = 3   # AP -> STA: ANonce + MIC + Install
    elif not has_ack and has_mic and has_secure:
        msg_num = 4   # STA -> AP: MIC + Secure
    else:
        return None

    pmkid = _extract_pmkid(raw_eapol) if msg_num == 1 else None

    return {
        "message_num": msg_num,
        "key_info": key_info,
        "replay_counter": replay_counter,
        "nonce": nonce,
        "mic": mic,
        "raw": raw_eapol,
        "pmkid": pmkid,
    }


def _extract_pmkid(raw_eapol: bytes) -> bytes | None:
    """Extract PMKID from EAPOL M1 Key Data (RSN KDE with OUI 00:0f:ac type 04)."""
    if len(raw_eapol) < 101:
        return None

    key_data_length = struct.unpack(">H", raw_eapol[97:99])[0]
    if key_data_length == 0:
        return None

    key_data = raw_eapol[99:99 + key_data_length]
    i = 0
    while i < len(key_data):
        tag = key_data[i]
        if i + 1 >= len(key_data):
            break
        length = key_data[i + 1]
        if tag == 0xDD and length >= 20:
            # Check OUI + Type: 00:0f:ac:04 (PMKID KDE)
            if i + 2 + 4 <= len(key_data) and key_data[i + 2:i + 6] == b'\x00\x0f\xac\x04':
                pmkid = key_data[i + 6:i + 6 + 16]
                if len(pmkid) == 16 and pmkid != b'\x00' * 16:
                    return pmkid
        # Advance: 2 bytes (tag + length) + length
        i += 2 + length
        if length == 0:
            break

    return None


class HandshakeTracker:
    """Track WPA 4-way handshakes and write hc22000 for hashcat (mode 22000)."""

    def __init__(self, output_dir: str = HANDSHAKE_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.sessions: dict[tuple, dict] = defaultdict(dict)
        self.completed: set[tuple] = set()
        self.essid_map: dict[str, str] = {}
        self.capture_count = 0
        self._pcap_writer = None

    def update_essid(self, bssid: str, ssid: str):
        """Feed BSSID-to-SSID mapping from beacons."""
        if ssid:
            self.essid_map[bssid.lower()] = ssid

    def _get_pcap_writer(self):
        """Lazy-init pcap writer for raw EAPOL backup."""
        if self._pcap_writer is None:
            try:
                from scapy.utils import PcapWriter
                path = self.output_dir / "eapol_raw.pcap"
                self._pcap_writer = PcapWriter(str(path), append=True, sync=True)
            except Exception:
                pass
        return self._pcap_writer

    def add_eapol(self, packet, ap_mac: str, sta_mac: str) -> dict | None:
        """Process a captured EAPOL packet.

        Returns handshake dict if a complete pair was assembled, else None.
        """
        # Backup raw packet to pcap (hcxpcapngtool can also convert this)
        writer = self._get_pcap_writer()
        if writer:
            try:
                writer.write(packet)
            except Exception:
                pass

        # Extract raw EAPOL bytes
        try:
            from scapy.layers.eap import EAPOL
            if not packet.haslayer(EAPOL):
                return None
            raw_eapol = bytes(packet[EAPOL])
        except Exception:
            return None

        parsed = parse_eapol_key(raw_eapol)
        if parsed is None:
            return None

        msg_num = parsed["message_num"]
        ap = ap_mac.lower()
        sta = sta_mac.lower()

        parsed["timestamp"] = time.time()
        key = (ap, sta)
        self.sessions[key][msg_num] = parsed

        logger.debug("EAPOL M%d: %s <-> %s", msg_num, ap, sta)

        # PMKID from M1 — can be cracked without full handshake
        if msg_num == 1 and parsed.get("pmkid"):
            pmkid_result = self._write_pmkid(ap, sta, parsed["pmkid"])
            if pmkid_result:
                return pmkid_result

        # Try to assemble a complete handshake pair
        msgs = self.sessions[key]
        result = None

        # Prefer M1+M2 (msg_pair 0), fall back to M2+M3 (msg_pair 2)
        if 1 in msgs and 2 in msgs:
            result = self._write_hc22000(ap, sta, msgs[1], msgs[2], msg_pair=0)
        if result is None and 2 in msgs and 3 in msgs:
            result = self._write_hc22000(ap, sta, msgs[3], msgs[2], msg_pair=2)

        if result:
            self.sessions.pop(key, None)

        return result

    def _write_hc22000(self, ap_mac, sta_mac, ap_msg, sta_msg, msg_pair) -> dict | None:
        """Assemble and append one hc22000 line (hashcat mode 22000).

        Format: WPA*02*MIC*MAC_AP*MAC_STA*ESSID_HEX*ANONCE*EAPOL_MIC_ZEROED*MP
        """
        essid = self.essid_map.get(ap_mac, "")
        if not essid:
            return None

        if (ap_mac, sta_mac, essid) in self.completed:
            return None

        anonce = ap_msg["nonce"]
        mic = sta_msg["mic"]

        # Zero MIC field in STA's EAPOL frame (bytes 81-96)
        eapol_zeroed = bytearray(sta_msg["raw"])
        eapol_zeroed[81:97] = b'\x00' * 16

        hc_line = (
            f"WPA*02*"
            f"{mic.hex()}*"
            f"{ap_mac.replace(':', '')}*"
            f"{sta_mac.replace(':', '')}*"
            f"{essid.encode().hex()}*"
            f"{anonce.hex()}*"
            f"{bytes(eapol_zeroed).hex()}*"
            f"{msg_pair:02d}"
        )

        out_file = self.output_dir / "captured.hc22000"
        with open(out_file, "a") as f:
            f.write(hc_line + "\n")

        self.completed.add((ap_mac, sta_mac, essid))
        self.capture_count += 1

        logger.info(
            "HANDSHAKE: %s (%s <-> %s) M%d+M%d [total: %d]",
            essid, ap_mac, sta_mac,
            ap_msg["message_num"], sta_msg["message_num"],
            self.capture_count,
        )

        return {
            "essid": essid,
            "ap_mac": ap_mac,
            "sta_mac": sta_mac,
            "msg_pair": msg_pair,
            "file": str(out_file),
        }

    def _write_pmkid(self, ap_mac, sta_mac, pmkid_bytes) -> dict | None:
        """Write a PMKID line to the hc22000 file (hashcat type 01)."""
        essid = self.essid_map.get(ap_mac, "")
        if not essid:
            return None

        dup_key = (ap_mac, sta_mac, essid, "pmkid")
        if dup_key in self.completed:
            return None

        hc_line = (
            f"WPA*01*"
            f"{pmkid_bytes.hex()}*"
            f"{ap_mac.replace(':', '')}*"
            f"{sta_mac.replace(':', '')}*"
            f"{essid.encode().hex()}*"
            f"**"
        )

        out_file = self.output_dir / "captured.hc22000"
        with open(out_file, "a") as f:
            f.write(hc_line + "\n")

        self.completed.add(dup_key)
        self.capture_count += 1

        logger.info(
            "PMKID: %s (%s <-> %s) [total: %d]",
            essid, ap_mac, sta_mac, self.capture_count,
        )

        return {
            "essid": essid,
            "ap_mac": ap_mac,
            "sta_mac": sta_mac,
            "type": "pmkid",
            "file": str(out_file),
        }

    def cleanup_stale(self, max_age: float = 30.0):
        """Drop incomplete handshake sessions older than max_age seconds."""
        now = time.time()
        stale = [
            k for k, msgs in self.sessions.items()
            if all(now - m["timestamp"] > max_age for m in msgs.values())
        ]
        for k in stale:
            del self.sessions[k]

    @property
    def stats(self) -> dict:
        return {
            "completed": self.capture_count,
            "pending": len(self.sessions),
            "essids": len(self.essid_map),
        }
