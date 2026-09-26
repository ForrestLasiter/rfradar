"""Saving what we've learned to a small SQLite database, so it survives restarts.

SQLite ships with Python — no server to run. Devices are stored as a JSON blob
per row: flexible (new fields don't need a schema migration) and easy to read.

Privacy: everything stays on this machine, and ordinary devices are forgotten
after ``retention_days``. Devices you marked "mine" and places are kept.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import Device, Place

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (key TEXT PRIMARY KEY, last_seen REAL, mine INTEGER, data TEXT);
CREATE TABLE IF NOT EXISTS places  (id INTEGER PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS trusted (ssid TEXT, bssid TEXT, PRIMARY KEY (ssid, bssid));
"""


def default_db_path() -> Path:
    return Path.home() / ".local" / "share" / "rfradar" / "rfradar.db"


class Store:
    def __init__(self, path: Path | str | None):
        # ":memory:" (or None) = a throwaway database, used by demo mode and tests.
        target = ":memory:" if path in (None, ":memory:") else str(path)
        if target != ":memory:":
            Path(target).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(target, check_same_thread=False)
        self.db.executescript(SCHEMA)

    # --- devices
    def load_devices(self) -> list[Device]:
        rows = self.db.execute("SELECT data FROM devices").fetchall()
        return [Device.from_json(json.loads(r[0])) for r in rows]

    def save_devices(self, devices: list[Device]) -> None:
        self.db.executemany(
            "INSERT OR REPLACE INTO devices VALUES (?, ?, ?, ?)",
            [(d.key, d.last_seen, int(d.mine), json.dumps(d.to_json())) for d in devices],
        )
        self.db.commit()

    def purge(self, older_than: float) -> int:
        cur = self.db.execute("DELETE FROM devices WHERE last_seen < ? AND mine = 0", (older_than,))
        self.db.commit()
        return cur.rowcount

    # --- places
    def load_places(self) -> list[Place]:
        out = []
        for (data,) in self.db.execute("SELECT data FROM places"):
            d = json.loads(data)
            d["fingerprint"] = set(d["fingerprint"])
            out.append(Place(**d))
        return out

    def save_places(self, places: list[Place]) -> None:
        rows = []
        for p in places:
            d = dict(p.__dict__)
            d["fingerprint"] = sorted(p.fingerprint)
            rows.append((p.id, json.dumps(d)))
        self.db.executemany("INSERT OR REPLACE INTO places VALUES (?, ?)", rows)
        self.db.commit()

    # --- trusted networks
    def load_trusted(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for ssid, bssid in self.db.execute("SELECT ssid, bssid FROM trusted"):
            out.setdefault(ssid, set()).add(bssid)
        return out

    def trust(self, ssid: str, bssids: set[str]) -> None:
        self.db.executemany("INSERT OR IGNORE INTO trusted VALUES (?, ?)", [(ssid, b) for b in bssids])
        self.db.commit()

    def untrust(self, ssid: str) -> None:
        self.db.execute("DELETE FROM trusted WHERE ssid = ?", (ssid,))
        self.db.commit()
