"""A scripted, fake radio environment — for demos, development and tests.

You "walk" Home → Coffee shop → Office → Home. Along the way:

* an AirTag that isn't yours is with you everywhere  → tracker + follower alerts
* the coffee shop has an open copy of its own Wi-Fi  → evil-twin alert
* someone at the coffee shop floods deauth frames    → deauth alert
* your own phone and earbuds are with you everywhere → mark them "mine"

No radio needed, so it runs anywhere (including Windows).
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import AsyncIterator

from ..models import Deauth, Kind, Sighting
from .base import Source


def _mac(prefix: str, n: int) -> str:
    return f"{prefix}:{n // 256:02x}:{n % 256:02x}"


# (ssid, bssid, channel, security, base rssi)
PLACES = {
    "home": [
        ("Home-5G", "a4:2b:b0:10:00:01", 36, "WPA3", -42),
        ("Home-2.4", "a4:2b:b0:10:00:02", 6, "WPA2", -48),
        ("NETGEAR47", "9c:3d:cf:22:11:05", 1, "WPA2", -71),
        ("xfinitywifi", "3c:37:86:40:aa:10", 11, "OPEN", -79),
        ("DIRECT-4F-HP OfficeJet", "fa:34:e2:00:4f:01", 6, "WPA2", -66),
        ("SpectrumSetup-C2", "10:93:97:55:c2:01", 1, "WPA2", -83),
    ],
    "coffee": [
        ("BeanThere_Guest", "00:1a:1e:77:30:01", 1, "WPA2", -52),
        ("BeanThere_Guest", "00:1a:1e:77:30:02", 44, "WPA2", -58),
        ("BeanThere_Guest", "02:13:37:be:ef:01", 6, "OPEN", -47),   # the evil twin
        ("ATT-WIFI-2231", "88:71:b1:12:22:31", 11, "WPA2", -74),
        ("Pharmacy-POS", "00:0c:e6:44:10:10", 6, "WPA2", -80),
        ("iPhone (Dana)", "5e:21:9a:00:00:01", 6, "WPA2", -69),
    ],
    "office": [
        ("Corp-Secure", "70:3a:0e:80:00:01", 36, "WPA3", -50),
        ("Corp-Secure", "70:3a:0e:80:00:02", 149, "WPA3", -60),
        ("Corp-Guest", "70:3a:0e:80:00:11", 1, "WPA2", -55),
        ("Conference-TV", "d8:31:34:66:66:01", 6, "WPA2", -72),
        ("Suite200", "b0:be:76:20:02:00", 11, "WPA2", -77),
    ],
}

ROUTE = ["home", "coffee", "office", "home"]

YOUR_PHONE = "7a:11:22:33:44:55"     # randomised Wi-Fi MAC, probes for your home network
YOUR_EARBUDS = "c8:69:cd:10:20:30"
STRANGE_AIRTAG = "e1:5c:4e:a9:07:3d"
CAFE_TILE = "d6:10:88:4e:21:77"

APPLE_SEPARATED = {0x004C: bytes([0x12, 0x19, 0x10]) + bytes(24)}
APPLE_NEARBY = {0x004C: bytes([0x10, 0x05, 0x01, 0x18, 0x44, 0x00, 0x00])}


class SimSource(Source):
    name = "demo simulator"

    def __init__(self, seconds_per_place: float = 45.0, seed: int | None = 7):
        super().__init__()
        self.dwell = seconds_per_place
        self.rng = random.Random(seed)

    def _j(self, base: int, spread: int = 6) -> int:
        return base + self.rng.randint(-spread, spread)

    async def stream(self) -> AsyncIterator[Sighting | Deauth]:
        from ..signatures import classify_ble

        self.status = "running (simulated walk: home → coffee shop → office → home)"
        start = time.time()
        while True:
            elapsed = time.time() - start
            leg = int(elapsed // self.dwell) % len(ROUTE)
            where = ROUTE[leg]
            t_in = elapsed % self.dwell
            now = time.time()
            self.status = f"running — simulated location: {where}"

            for ssid, bssid, ch, sec, rssi in PLACES[where]:
                if self.rng.random() < 0.85:
                    yield Sighting(Kind.AP, bssid, now, self._j(rssi), name=ssid, channel=ch,
                                   security=sec, source="sim")

            # Things that travel with you.
            yield Sighting(Kind.CLIENT, YOUR_PHONE, now, self._j(-38), probed_ssid="Home-5G", source="sim")
            yield Sighting(Kind.BLE, YOUR_EARBUDS, now, self._j(-45), name="My AirPods",
                           vendor="Apple", source="sim")
            tag = classify_ble(APPLE_SEPARATED)
            yield Sighting(Kind.BLE, STRANGE_AIRTAG, now, self._j(-61), vendor="Apple",
                           tracker=tag.label, tracker_state=tag.state, source="sim")

            # Local colour: strangers' phones (random MACs) and gadgets.
            for i in range(self.rng.randint(2, 5)):
                yield Sighting(Kind.CLIENT, _mac(f"{self.rng.choice('26ae')}2:{leg:02x}:5a:9f", i),
                               now, self._j(-78, 10), probed_ssid=self.rng.choice(
                                   [None, "Starbucks WiFi", "linksys", "MOTEL6", "Airport_Free"]),
                               source="sim")
            for i in range(self.rng.randint(1, 4)):
                yield Sighting(Kind.BLE, _mac(f"4{leg}:c1:0d:77", i), now, self._j(-80, 8),
                               vendor="Apple" if i % 2 else None, source="sim")

            if where == "coffee":
                tile = classify_ble(service_uuids=["0000feed-0000-1000-8000-00805f9b34fb"])
                yield Sighting(Kind.BLE, CAFE_TILE, now, self._j(-74), tracker=tile.label,
                               tracker_state=tile.state, source="sim")
                yield Sighting(Kind.CLIENT, "b8:27:eb:5a:11:02", now, self._j(-60),
                               bssid="00:1a:1e:77:30:01", vendor="Raspberry Pi", source="sim")
                if self.dwell * 0.4 < t_in < self.dwell * 0.6:  # the attack
                    for _ in range(12):
                        yield Deauth(now, "00:1a:1e:77:30:01", "ff:ff:ff:ff:ff:ff",
                                     "00:1a:1e:77:30:01", source="sim")
            if where == "office":
                yield Sighting(Kind.BLE, YOUR_EARBUDS, now, self._j(-50), source="sim")
                yield Sighting(Kind.BLE, "f0:99:b6:31:0a:02", now, self._j(-70), name="Pixel Watch",
                               vendor="Google", source="sim")

            await asyncio.sleep(1.0)
