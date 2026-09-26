"""The small set of data shapes everything else passes around.

Sources (Wi-Fi, Bluetooth, the demo simulator) produce *observations*:
``Sighting`` ("I heard device X just now") and ``Deauth`` ("someone just sent a
kick-off frame"). The engine folds sightings into ``Device`` records, and the
analyzers turn devices into ``Alert`` objects for the dashboard.

Why dataclasses? They give us a typed, self-documenting "record" with almost no
code — Python writes ``__init__`` and ``__repr__`` for us.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Kind(str, Enum):
    """What sort of thing we heard. Inheriting from ``str`` makes it JSON-friendly."""

    AP = "ap"          # a Wi-Fi access point / hotspot (it sends "beacons")
    CLIENT = "client"  # a Wi-Fi device: phone, laptop, camera...
    BLE = "ble"        # a Bluetooth Low Energy device: tracker, earbuds, watch...


class Severity(str, Enum):
    INFO = "info"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Sighting:
    """One moment of hearing one device."""

    kind: Kind
    mac: str                        # hardware address, always lower-case "aa:bb:cc:dd:ee:ff"
    ts: float                       # unix time we heard it
    rssi: int | None = None         # signal strength in dBm (-30 = very close, -90 = far)
    name: str | None = None         # Wi-Fi network name (SSID) or Bluetooth device name
    channel: int | None = None
    security: str | None = None     # APs only: OPEN / WEP / WPA / WPA2 / WPA3
    probed_ssid: str | None = None  # a client asking "is network X here?"
    bssid: str | None = None        # the access point a client is talking to
    vendor: str | None = None
    tracker: str | None = None      # BLE: e.g. "Apple Find My" if it looks like a tracker
    tracker_state: str | None = None  # "separated" (away from its owner) / "near-owner"
    source: str = ""


@dataclass
class Deauth:
    """A deauthentication/disassociation frame — the "get off this network" message.

    A few are normal. A burst of them is the classic sign of someone forcing
    devices to disconnect (often to push them onto an evil twin).
    """

    ts: float
    src: str
    dst: str
    bssid: str
    source: str = ""


@dataclass
class Device:
    """Everything we've learned about one device, accumulated over time."""

    kind: Kind
    mac: str
    first_seen: float
    last_seen: float
    rssi: int | None = None
    rssi_best: int | None = None
    names: set[str] = field(default_factory=set)
    channel: int | None = None
    security: str | None = None
    probes: set[str] = field(default_factory=set)
    bssid: str | None = None
    vendor: str | None = None
    randomized: bool = False        # privacy MAC (changes over time) — see oui.is_randomized
    tracker: str | None = None
    tracker_state: str | None = None
    places: set[int] = field(default_factory=set)  # Places it has *really* been at (see engine.tick)
    place_ticks: dict[int, int] = field(default_factory=dict)  # evidence so far, per place
    mine: bool = False              # the user marked this as their own device
    count: int = 0

    @property
    def key(self) -> str:
        return f"{self.kind.value}/{self.mac}"

    def to_json(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind.value
        # sets aren't JSON; sorted lists are stable and readable.
        for k in ("names", "probes", "places"):
            d[k] = sorted(d[k])
        return d

    @classmethod
    def from_json(cls, d: dict) -> "Device":
        d = dict(d)
        d["kind"] = Kind(d["kind"])
        for k in ("names", "probes", "places"):
            d[k] = set(d.get(k, []))
        # JSON turns dict keys into strings; turn them back into place ids.
        d["place_ticks"] = {int(k): v for k, v in d.get("place_ticks", {}).items()}
        return cls(**d)


@dataclass
class Place:
    """A location, recognised purely by *which Wi-Fi networks are visible there*.

    The laptop has no GPS, but the set of access points around you is a very
    good fingerprint of where you are (it's how phones locate themselves indoors).
    """

    id: int
    label: str
    fingerprint: set[str]  # BSSIDs of the access points seen there
    first_seen: float
    last_seen: float

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "aps": len(self.fingerprint),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class Alert:
    key: str               # stable id so the same problem updates instead of duplicating
    severity: Severity
    title: str
    detail: str
    macs: list[str]
    first_seen: float
    last_seen: float

    def to_json(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
