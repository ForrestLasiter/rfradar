"""Recognising Bluetooth item trackers from their advertisements.

Every BLE device periodically shouts a short "advertisement" packet. Trackers
(AirTags, Tiles, SmartTags...) have tell-tale patterns in those packets. This
module is *pure logic* — it takes already-decoded advertisement fields and
returns a label — so it's easy to unit-test without any radio.

Signatures are best-effort: vendors change formats, so each one carries a
comment about what it matches and how sure we are.
"""

from __future__ import annotations

from dataclasses import dataclass

APPLE = 0x004C


def _uuid16(u: str) -> str:
    """Normalise "0000feed-0000-1000-8000-00805f9b34fb" or "feed" to "feed"."""
    u = u.lower()
    if len(u) == 36 and u.endswith("-0000-1000-8000-00805f9b34fb"):
        return u[4:8]
    return u


@dataclass(frozen=True)
class TrackerMatch:
    label: str
    state: str | None  # "separated" = away from its owner (the stalking-relevant case)


def classify_ble(
    manufacturer_data: dict[int, bytes] | None = None,
    service_data: dict[str, bytes] | None = None,
    service_uuids: list[str] | None = None,
) -> TrackerMatch | None:
    manufacturer_data = manufacturer_data or {}
    service_data = {_uuid16(k): v for k, v in (service_data or {}).items()}
    uuids = {_uuid16(u) for u in (service_uuids or [])} | set(service_data)

    # Apple "Find My" / Offline Finding: Apple manufacturer data whose first byte
    # (the Apple message type) is 0x12. The second byte is the payload length:
    # 25 (0x19) = the full public-key broadcast a device sends when it's been
    # SEPARATED from its owner — exactly what a planted AirTag does. A 2-byte
    # payload is the short "I'm near my owner" form. (High confidence.)
    apple = manufacturer_data.get(APPLE)
    if apple and len(apple) >= 2 and apple[0] == 0x12:
        state = "separated" if apple[1] >= 0x19 else "near-owner"
        return TrackerMatch("Apple Find My (AirTag or Find My accessory)", state)

    # Samsung Galaxy SmartTag: service data on 16-bit UUID 0xFD5A. (High.)
    if "fd5a" in uuids:
        return TrackerMatch("Samsung SmartTag", None)

    # Tile: advertises service 0xFEED (and 0xFEEC on some models). (High.)
    if "feed" in uuids or "feec" in uuids:
        return TrackerMatch("Tile", None)

    # Chipolo: service 0xFE33. (Medium — verify against a real tag.)
    if "fe33" in uuids:
        return TrackerMatch("Chipolo", None)

    # Google Find My Device network tags use Eddystone service data (0xFEAA)
    # with frame type 0x40/0x41. (Medium — verify against a real tag.)
    eddy = service_data.get("feaa")
    if eddy and eddy[:1] in (b"\x40", b"\x41"):
        return TrackerMatch("Google Find My Device tag", None)

    return None
