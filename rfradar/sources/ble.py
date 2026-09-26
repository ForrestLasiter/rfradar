"""Bluetooth Low Energy scanning — works with the laptop's built-in Bluetooth.

Uses `bleak`, which talks to Linux's BlueZ stack over D-Bus. A *passive* scan
only listens to advertisements; it doesn't connect to anything.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator

from ..models import Kind, Sighting
from ..oui import BLE_COMPANIES, norm
from ..signatures import classify_ble
from .base import Source


def sighting_from_adv(address: str, adv, now: float, source: str = "ble") -> Sighting:
    """Pure conversion from a bleak AdvertisementData (or look-alike) to a Sighting."""
    m = adv.manufacturer_data or {}
    match = classify_ble(m, adv.service_data or {}, adv.service_uuids or [])
    vendor = next((BLE_COMPANIES[c] for c in m if c in BLE_COMPANIES), None)
    return Sighting(Kind.BLE, norm(address), now, adv.rssi, name=adv.local_name or None,
                    vendor=vendor, tracker=match.label if match else None,
                    tracker_state=match.state if match else None, source=source)


class BleSource(Source):
    name = "Bluetooth LE"

    async def stream(self) -> AsyncIterator[Sighting]:
        from bleak import BleakScanner

        queue: asyncio.Queue = asyncio.Queue(maxsize=20000)

        def on_adv(device, adv):
            queue.put_nowait(sighting_from_adv(device.address, adv, time.time(), self.name))

        # Honest caveat: bleak's default is an *active* scan, which sends tiny "scan
        # request" packets to get a device's name. It never connects or pairs, but it
        # isn't strictly silent. True passive scanning on BlueZ needs its experimental
        # advertisement-monitor API — tracked as a Phase 2 item in docs/DESIGN.md.
        async with BleakScanner(detection_callback=on_adv):
            self.status = "running"
            while True:
                yield await queue.get()
