"""Lightweight Wi-Fi scanning with the laptop's *built-in* card — no Alfa needed.

This just asks NetworkManager for its normal "available networks" list every
so often, so your Wi-Fi connection keeps working. It sees access points only
(not individual devices or deauth frames), which is still enough for the
"where am I" fingerprint and evil-twin detection.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import AsyncIterator

from ..models import Kind, Sighting
from .base import Source

# nmcli -t output separates fields with ':' and escapes literal colons as '\:'.
_SPLIT = re.compile(r"(?<!\\):")


def security_from_nm(text: str) -> str:
    t = text.upper()
    for level in ("WPA3", "WPA2", "WPA1", "WEP"):
        if level in t:
            return "WPA" if level == "WPA1" else level
    if "SAE" in t or "OWE" in t:
        return "WPA3"
    return "OPEN"


def parse_nmcli(output: str, now: float, source: str = "nmcli") -> list[Sighting]:
    out = []
    for line in output.splitlines():
        parts = [p.replace("\\:", ":").replace("\\\\", "\\") for p in _SPLIT.split(line)]
        if len(parts) < 5:
            continue
        bssid, ssid, chan, signal, sec = parts[:5]
        try:
            # nmcli gives 0-100 "signal quality"; this is the usual rough dBm conversion.
            rssi = int(int(signal) / 2 - 100)
            channel = int(chan)
        except ValueError:
            continue
        out.append(Sighting(Kind.AP, bssid.lower(), now, rssi, name=ssid or None, channel=channel,
                            security=security_from_nm(sec), source=source))
    return out


class WifiScanSource(Source):
    name = "Wi-Fi scan (NetworkManager)"

    def __init__(self, interval: float = 20.0):
        super().__init__()
        self.interval = interval

    async def stream(self) -> AsyncIterator[Sighting]:
        while True:
            proc = await asyncio.create_subprocess_exec(
                "nmcli", "-t", "-e", "yes", "-f", "BSSID,SSID,CHAN,SIGNAL,SECURITY",
                "device", "wifi", "list", "--rescan", "yes",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await proc.communicate()
            if proc.returncode != 0:
                self.status = f"nmcli error: {err.decode().strip()[:120]}"
            else:
                found = parse_nmcli(out.decode(errors="replace"), time.time(), self.name)
                self.status = f"running — {len(found)} networks in last scan"
                for s in found:
                    yield s
            await asyncio.sleep(self.interval)
