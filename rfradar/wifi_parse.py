"""Turn raw 802.11 (Wi-Fi) frames into Sightings.

In monitor mode the adapter hands us *every* frame it hears, not just ones for
us. We only look at the envelope — management frames (beacons, probe requests,
deauths) and the addresses on data frames. We never look inside the payload.

Pure function of a scapy packet, so it's unit-tested with hand-built frames.
"""

from __future__ import annotations

from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
    RadioTap,
)

from .models import Deauth, Kind, Sighting
from .oui import is_multicast, norm


def security_from_crypto(crypto: set[str]) -> str:
    """scapy reports e.g. {"WPA2/PSK"} or {"OPN"}; boil it down to one word."""
    text = " ".join(crypto).upper()
    for level in ("WPA3", "WPA2", "WPA", "WEP"):
        if level in text:
            return level
    return "OPEN"


def _rssi(pkt) -> int | None:
    if pkt.haslayer(RadioTap):
        val = getattr(pkt[RadioTap], "dBm_AntSignal", None)
        if val is not None:
            return int(val)
    return None


def _clean_ssid(raw) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    raw = raw.strip("\x00")
    return raw or None  # empty = a "hidden" network


def parse_frame(pkt, now: float, source: str = "wifi") -> list[Sighting | Deauth]:
    if not pkt.haslayer(Dot11):
        return []
    d = pkt[Dot11]
    rssi = _rssi(pkt)
    out: list[Sighting | Deauth] = []

    # --- Access points announce themselves with beacons / probe responses.
    for layer in (Dot11Beacon, Dot11ProbeResp):
        if pkt.haslayer(layer):
            stats = pkt[layer].network_stats()
            out.append(
                Sighting(
                    kind=Kind.AP,
                    mac=norm(d.addr3 or d.addr2),
                    ts=now,
                    rssi=rssi,
                    name=_clean_ssid(stats.get("ssid")),
                    channel=stats.get("channel"),
                    security=security_from_crypto(stats.get("crypto", set())),
                    source=source,
                )
            )
            return out

    # --- A device asking "is <network> here?" leaks networks it has joined before.
    if pkt.haslayer(Dot11ProbeReq):
        ssid = None
        elt = pkt.getlayer(Dot11Elt, ID=0)
        if elt is not None:
            ssid = _clean_ssid(elt.info)
        out.append(Sighting(Kind.CLIENT, norm(d.addr2), now, rssi, probed_ssid=ssid, source=source))
        return out

    # --- Kick-off frames.
    for layer in (Dot11Deauth, Dot11Disas):
        if pkt.haslayer(layer):
            out.append(Deauth(now, norm(d.addr2), norm(d.addr1), norm(d.addr3), source=source))
            return out

    # --- Data frames: we only read the address fields, to learn who talks to which AP.
    if d.type == 2:
        to_ds = bool(d.FCfield & 0x1)
        from_ds = bool(d.FCfield & 0x2)
        if to_ds and not from_ds:      # device -> AP
            client, bssid = d.addr2, d.addr1
        elif from_ds and not to_ds:    # AP -> device
            client, bssid = d.addr1, d.addr2
        else:
            return out
        if client and not is_multicast(client):
            out.append(Sighting(Kind.CLIENT, norm(client), now, rssi if to_ds else None,
                                bssid=norm(bssid), source=source))
    return out
