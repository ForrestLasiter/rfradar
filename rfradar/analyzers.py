"""The detection rules. Each function looks at current state and returns Alerts.

Kept as plain functions (no radio, no clock of their own) so tests can feed
them hand-made devices and check exactly what fires.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from .models import Alert, Deauth, Device, Kind, Severity
from .settings import Settings


def _alert(key, sev, title, detail, macs, now) -> Alert:
    return Alert(key, sev, title, detail, sorted(macs), now, now)


def _minutes(seconds: float) -> str:
    m = int(seconds // 60)
    return f"{m} min" if m >= 1 else f"{int(seconds)} s"


def evil_twins(aps: Iterable[Device], trusted: dict[str, set[str]], now: float) -> list[Alert]:
    """Hotspots that look like impostors.

    1. Same network name broadcast both OPEN and encrypted — the textbook evil
       twin: attackers clone a name but can't know the password, so their copy
       is open. (WPA2-vs-WPA3 differences are normal and ignored.)
    2. A network you marked *trusted* appearing from an access point you've
       never seen it on before.
    3. One access point shouting lots of different names, including open ones
       — a "karma" style rogue that answers to whatever devices ask for.
    """
    aps = list(aps)
    alerts: list[Alert] = []
    by_ssid: dict[str, list[Device]] = defaultdict(list)
    by_bssid_names: dict[str, set[str]] = defaultdict(set)
    for ap in aps:
        for name in ap.names:
            by_ssid[name].append(ap)
            by_bssid_names[ap.mac].add(name)

    for ssid, group in by_ssid.items():
        secs = {ap.security or "OPEN" for ap in group}
        weak = secs & {"OPEN", "WEP"}
        strong = secs - {"OPEN", "WEP"}
        if weak and strong:
            open_aps = [ap.mac for ap in group if (ap.security or "OPEN") in weak]
            alerts.append(_alert(
                f"twin/{ssid}", Severity.HIGH,
                f"Possible evil twin: “{ssid}”",
                f"“{ssid}” is being broadcast both secured ({', '.join(sorted(strong))}) and "
                f"{'/'.join(sorted(weak)).lower()} by {len(open_aps)} access point(s). "
                "Don't join the unsecured one.",
                [ap.mac for ap in group], now))

        if ssid in trusted:
            unknown = [ap.mac for ap in group if ap.mac not in trusted[ssid]]
            if unknown:
                alerts.append(_alert(
                    f"trusted/{ssid}", Severity.MEDIUM,
                    f"New access point for trusted network “{ssid}”",
                    f"{len(unknown)} access point(s) you haven't seen before are using the name "
                    f"of your trusted network. Could be a new router — or an impersonator.",
                    unknown, now))

    for bssid, names in by_bssid_names.items():
        if len(names) >= 4:
            ap = next(a for a in aps if a.mac == bssid)
            if (ap.security or "OPEN") == "OPEN":
                alerts.append(_alert(
                    f"karma/{bssid}", Severity.MEDIUM,
                    "One access point using many network names",
                    f"{bssid} is broadcasting {len(names)} different names while open "
                    f"({', '.join(sorted(names)[:5])}…). Rogue hotspots do this to lure devices.",
                    [bssid], now))
    return alerts


def deauth_bursts(events: Iterable[Deauth], s: Settings, now: float) -> list[Alert]:
    """Lots of kick-off frames from one network in a few seconds."""
    per_bssid: dict[str, list[Deauth]] = defaultdict(list)
    for e in events:
        if now - e.ts <= s.deauth_window_s:
            per_bssid[e.bssid].append(e)
    alerts = []
    for bssid, evs in per_bssid.items():
        if len(evs) >= s.deauth_burst:
            victims = {e.dst for e in evs}
            alerts.append(_alert(
                f"deauth/{bssid}", Severity.HIGH,
                "Devices are being forced off a network",
                f"{len(evs)} deauthentication frames in {int(s.deauth_window_s)} s on {bssid} "
                f"({len(victims)} target(s)). This is how attackers push people onto a fake hotspot.",
                [bssid], now))
    return alerts


def trackers(devices: Iterable[Device], s: Settings, now: float) -> list[Alert]:
    """Item trackers that are away from their owner and have stuck around you."""
    alerts = []
    for d in devices:
        if d.mine or not d.tracker or d.tracker_state == "near-owner":
            continue
        if now - d.last_seen > s.active_s:
            continue
        span = d.last_seen - d.first_seen
        if span >= s.tracker_linger_s:
            alerts.append(_alert(
                f"tracker/{d.mac}", Severity.MEDIUM,
                f"Unknown tracker nearby for {_minutes(span)}",
                f"An item tracker ({d.tracker}) that isn't with its owner has been near you for "
                f"{_minutes(span)}. "
                "If it keeps turning up, check your bag, car and pockets.",
                [d.mac], now))
    return alerts


def followers(devices: Iterable[Device], places_known: int, s: Settings, now: float) -> list[Alert]:
    """Devices that have turned up at several different places you've been."""
    alerts = []
    if places_known < s.follow_watch_places:
        return alerts
    for d in devices:
        if d.mine or d.kind == Kind.AP:
            continue
        n = len(d.places)
        label = d.tracker or (sorted(d.names)[0] if d.names else None) or             f"{d.vendor or 'unnamed'} {'Bluetooth' if d.kind == Kind.BLE else 'Wi-Fi'} device"
        if n >= s.follow_places:
            sev = Severity.HIGH
            title = f"Following you: {label}"
        elif n >= s.follow_watch_places and d.tracker and d.tracker_state != "near-owner":
            sev = Severity.MEDIUM
            title = f"Seen at {n} of your places: {label}"
        else:
            continue
        note = (" Its address is randomised, so it may also be a coincidence." if d.randomized
                and not d.tracker else "")
        alerts.append(_alert(
            f"follow/{d.mac}", sev, title,
            f"{d.mac} has been heard at {n} different places you've been.{note} "
            "If it's yours, mark it as “mine”.",
            [d.mac], now))
    return alerts
