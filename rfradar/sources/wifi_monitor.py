"""Full Wi-Fi capture from an adapter in *monitor mode* (e.g. an Alfa).

Monitor mode lets the card hear every frame on a channel, not just traffic for
us. A card can only sit on one channel at a time, so a "hopper" thread keeps
retuning it across the 2.4 GHz and 5 GHz channels.

Listen-only: this module never calls sendp() or any other transmit function.
Needs root (raw sockets + `iw`). Linux only.
"""

from __future__ import annotations

import asyncio
import subprocess
import threading
import time
from collections.abc import AsyncIterator

from ..models import Deauth, Sighting
from .base import Source

CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 149, 153, 157, 161, 165]


def iface_mode(iface: str) -> str | None:
    try:
        out = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("type "):
            return line.split()[1]
    return None


class WifiMonitorSource(Source):
    def __init__(self, iface: str, dwell: float = 0.35, five_ghz: bool = True):
        super().__init__()
        self.iface = iface
        self.name = f"Wi-Fi monitor ({iface})"
        self.dwell = dwell
        self.channels = CHANNELS_24 + (CHANNELS_5 if five_ghz else [])
        self._stop = threading.Event()

    def _hop(self) -> None:
        bad: set[int] = set()
        while not self._stop.is_set():
            for ch in self.channels:
                if self._stop.is_set():
                    return
                if ch in bad:
                    continue
                r = subprocess.run(["iw", "dev", self.iface, "set", "channel", str(ch)],
                                   capture_output=True)
                if r.returncode != 0:
                    bad.add(ch)  # not allowed in this country / by this card — skip from now on
                    continue
                time.sleep(self.dwell)

    async def stream(self) -> AsyncIterator[Sighting | Deauth]:
        from scapy.sendrecv import AsyncSniffer

        from ..wifi_parse import parse_frame

        mode = iface_mode(self.iface)
        if mode != "monitor":
            raise RuntimeError(
                f"{self.iface} is in '{mode}' mode, not monitor. Run: sudo rfradar monitor {self.iface} on")

        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue(maxsize=20000)

        def on_packet(pkt):  # runs in scapy's thread — hand results to the event loop safely
            for obs in parse_frame(pkt, time.time(), source=self.name):
                loop.call_soon_threadsafe(queue.put_nowait, obs)

        # Only management + data frames' headers matter; BPF keeps the rest out of Python.
        sniffer = AsyncSniffer(iface=self.iface, prn=on_packet, store=False,
                               filter="type mgt or type data")
        sniffer.start()
        hopper = threading.Thread(target=self._hop, daemon=True)
        hopper.start()
        self.status = f"running — hopping {len(self.channels)} channels"
        try:
            while True:
                yield await queue.get()
        finally:
            self._stop.set()
            sniffer.stop()
