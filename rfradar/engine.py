"""The engine: the one place where observations become knowledge.

    sources ──(Sighting / Deauth)──▶ ingest() ──▶ devices
                                     tick()   ──▶ place fingerprint, alerts, save

Everything runs on one asyncio event loop, so there are no locks: sources
``await`` new data, and the engine updates its dictionaries between awaits.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque

from . import analyzers
from .models import Alert, Deauth, Device, Kind, Sighting
from .oui import is_randomized, vendor
from .places import PlaceTracker
from .settings import Settings
from .sources.base import Source
from .store import Store

log = logging.getLogger("rfradar")


class Engine:
    def __init__(self, settings: Settings, store: Store, clock=time.time):
        self.s = settings
        self.store = store
        self.clock = clock
        self.devices: dict[str, Device] = {d.key: d for d in store.load_devices()}
        self.places = PlaceTracker(settings.place_match, settings.place_min_aps)
        for p in store.load_places():
            self.places.places[p.id] = p
        self.trusted = store.load_trusted()
        self.deauths: deque[Deauth] = deque(maxlen=5000)
        self.alerts: dict[str, Alert] = {}
        self.muted: set[str] = set()  # alerts the user dismissed; don't raise them again
        self.sources: list[Source] = []
        self.started = clock()

    # ------------------------------------------------------------------ input
    def ingest(self, obs: Sighting | Deauth) -> None:
        if isinstance(obs, Deauth):
            self.deauths.append(obs)
            return

        key = f"{obs.kind.value}/{obs.mac}"
        d = self.devices.get(key)
        if d is None:
            d = Device(
                kind=obs.kind, mac=obs.mac, first_seen=obs.ts, last_seen=obs.ts,
                randomized=is_randomized(obs.mac),
                vendor=obs.vendor or vendor(obs.mac),
            )
            self.devices[key] = d
        d.last_seen = max(d.last_seen, obs.ts)
        d.count += 1
        if obs.rssi is not None:
            d.rssi = obs.rssi
            d.rssi_best = obs.rssi if d.rssi_best is None else max(d.rssi_best, obs.rssi)
        if obs.name:
            d.names.add(obs.name)
        if obs.channel:
            d.channel = obs.channel
        if obs.security:
            d.security = obs.security
        if obs.probed_ssid:
            d.probes.add(obs.probed_ssid)
        if obs.bssid:
            d.bssid = obs.bssid
        if obs.vendor and not d.vendor:
            d.vendor = obs.vendor
        if obs.tracker:
            d.tracker, d.tracker_state = obs.tracker, obs.tracker_state

    # ------------------------------------------------------------------ periodic work
    def active(self, now: float | None = None) -> list[Device]:
        now = now or self.clock()
        return [d for d in self.devices.values() if now - d.last_seen <= self.s.active_s]

    def tick(self, now: float | None = None) -> None:
        now = now or self.clock()

        # 1. Where are we? Fingerprint = strong APs heard recently.
        fp = {
            d.mac for d in self.devices.values()
            if d.kind == Kind.AP and now - d.last_seen <= self.s.place_window_s
            and (d.rssi is None or d.rssi >= self.s.place_min_rssi)
        }
        place = self.places.locate(fp, now)
        if place is not None:
            # Only credit devices heard since roughly the last tick — not everything in
            # the (longer) fingerprint window, or devices from the place you just LEFT
            # would be counted at the new one too.
            recent = self.s.tick_s * 1.5
            need = self.s.min_presence_ticks
            for d in self.devices.values():
                if d.kind != Kind.AP and now - d.last_seen <= recent:
                    n = d.place_ticks.get(place, 0) + 1
                    d.place_ticks[place] = n
                    if n >= need:
                        d.places.add(place)

        # 2. Run the rules on what's around right now.
        active = self.active(now)
        fresh: list[Alert] = []
        fresh += analyzers.evil_twins([d for d in active if d.kind == Kind.AP], self.trusted, now)
        fresh += analyzers.deauth_bursts(self.deauths, self.s, now)
        fresh += analyzers.trackers(active, self.s, now)
        fresh += analyzers.followers(active, len(self.places.places), self.s, now)
        for a in fresh:
            if a.key in self.muted:
                continue
            old = self.alerts.get(a.key)
            if old:  # same problem again: keep when it started, refresh the text
                a.first_seen = old.first_seen
            self.alerts[a.key] = a

        # 3. Persist, and forget old ordinary devices.
        self.store.save_devices(list(self.devices.values()))
        self.store.save_places(list(self.places.places.values()))
        cutoff = now - self.s.retention_days * 86400
        if self.store.purge(cutoff):
            self.devices = {k: d for k, d in self.devices.items() if d.mine or d.last_seen >= cutoff}

    # ------------------------------------------------------------------ user actions
    def set_mine(self, key: str, mine: bool) -> bool:
        d = self.devices.get(key)
        if not d:
            return False
        d.mine = mine
        # Clear any alerts about it straight away.
        self.alerts = {k: a for k, a in self.alerts.items() if d.mac not in a.macs or not mine}
        return True

    def label_place(self, place_id: int, label: str) -> bool:
        p = self.places.places.get(place_id)
        if not p:
            return False
        p.label = label.strip()[:60] or p.label
        return True

    def trust_ssid(self, ssid: str) -> int:
        bssids = {d.mac for d in self.devices.values() if d.kind == Kind.AP and ssid in d.names}
        self.store.trust(ssid, bssids)
        self.trusted = self.store.load_trusted()
        self.alerts.pop(f"trusted/{ssid}", None)
        return len(bssids)

    def dismiss(self, key: str) -> None:
        self.alerts.pop(key, None)
        self.muted.add(key)

    # ------------------------------------------------------------------ run loop
    async def run(self, sources: list[Source]) -> None:
        self.sources = sources

        async def pump(src: Source):
            try:
                async for obs in src.stream():
                    self.ingest(obs)
            except Exception as e:  # a broken source shouldn't take the others down
                src.status = f"stopped: {e}"
                log.exception("source %s failed", src.name)

        async def ticker():
            while True:
                await asyncio.sleep(self.s.tick_s)
                try:
                    self.tick()
                except Exception:
                    log.exception("tick failed")

        await asyncio.gather(ticker(), *(pump(s) for s in sources))

    # ------------------------------------------------------------------ for the dashboard
    def snapshot(self) -> dict:
        now = self.clock()
        by_kind: dict[str, list] = {"ap": [], "client": [], "ble": []}
        for d in sorted(self.devices.values(), key=lambda d: -(d.rssi or -200)):
            if now - d.last_seen <= self.s.active_s or d.mine or d.places and len(d.places) > 1:
                j = d.to_json()
                j["active"] = now - d.last_seen <= self.s.active_s
                j["trusted"] = any(n in self.trusted for n in d.names)
                by_kind[d.kind.value].append(j)
        sev_rank = {"high": 0, "medium": 1, "info": 2}
        alerts = sorted((a.to_json() for a in self.alerts.values()),
                        key=lambda a: (sev_rank[a["severity"]], -a["last_seen"]))
        for a in alerts:  # still happening, or just history until dismissed?
            a["ongoing"] = now - a["last_seen"] <= self.s.tick_s * 2.5
        cur = self.places.current
        return {
            "now": now,
            "uptime": now - self.started,
            "sources": [{"name": s.name, "status": s.status} for s in self.sources],
            "place": self.places.places[cur].to_json() if cur else None,
            "places": [p.to_json() for p in sorted(self.places.places.values(), key=lambda p: -p.last_seen)],
            "alerts": alerts,
            "devices": by_kind,
            "trusted": sorted(self.trusted),
        }
