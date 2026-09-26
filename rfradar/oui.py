"""Helpers for hardware (MAC) addresses.

The first three bytes of a MAC are the manufacturer's "OUI" — e.g. every Apple
chip starts with one of Apple's registered prefixes. Modern phones, though,
usually *invent* a random MAC for privacy, and they mark it by setting the
"locally administered" bit. Knowing which MACs are random matters: a random MAC
changes every so often, so "I saw it at 3 places" means much more for a device
with a real, fixed MAC.
"""

from __future__ import annotations

from functools import lru_cache


def norm(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def is_randomized(mac: str) -> bool:
    """True if the "locally administered" bit (0x02 of the first byte) is set."""
    try:
        return bool(int(norm(mac)[:2], 16) & 0x02)
    except ValueError:
        return False


def is_multicast(mac: str) -> bool:
    """Broadcast / multicast destinations aren't real devices."""
    try:
        return bool(int(norm(mac)[:2], 16) & 0x01)
    except ValueError:
        return True


@lru_cache(maxsize=4096)
def vendor(mac: str) -> str | None:
    """Manufacturer name from the OUI, if scapy + Wireshark's `manuf` file are present.

    On Kali, Wireshark ships /usr/share/wireshark/manuf and scapy reads it.
    Random MACs have no real vendor, so we don't even try.
    """
    if is_randomized(mac):
        return None
    try:
        from scapy.config import conf  # optional dependency

        db = conf.manufdb
        if db is None:
            return None
        name = db._get_manuf(norm(mac))  # returns the MAC itself when unknown
        return None if not name or norm(name) == norm(mac) else name
    except Exception:
        return None


# Bluetooth "company identifiers" (assigned by the Bluetooth SIG) seen in
# manufacturer-specific advertising data. A short list of the common ones.
BLE_COMPANIES = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x0087: "Garmin",
    0x0157: "Huami (Amazfit)",
    0x038F: "Xiaomi",
    0x0171: "Amazon",
    0x02E5: "Espressif",
}
