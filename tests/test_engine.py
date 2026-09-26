"""Detection rules and the engine, driven with hand-made observations and a fake clock."""

from rfradar.engine import Engine
from rfradar.models import Deauth, Kind, Sighting
from rfradar.places import PlaceTracker, jaccard
from rfradar.settings import Settings
from rfradar.store import Store


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def make():
    clock = Clock()
    s = Settings(tick_s=1, place_window_s=10, active_s=30, tracker_linger_s=60, presence_ticks=2)
    return Engine(s, Store(None), clock=clock), clock


def aps(engine, clock, prefix, n=4, sec="WPA2"):
    for i in range(n):
        engine.ingest(Sighting(Kind.AP, f"{prefix}:00:00:0{i}", clock.t, -50, name=f"{prefix}-{i}", security=sec))


def test_jaccard_and_places():
    assert jaccard({"a", "b"}, {"a", "b"}) == 1.0
    assert jaccard({"a"}, {"b"}) == 0.0
    pt = PlaceTracker(0.35, 3)
    home = pt.locate({"a", "b", "c", "d"}, 0)
    assert pt.locate({"a", "b", "c", "e"}, 1) == home      # mostly the same => same place
    assert pt.locate({"x", "y", "z"}, 2) != home           # different => new place
    assert pt.locate({"a", "b"}, 3) is None                 # too few APs => unknown


def test_evil_twin_fires():
    e, c = make()
    e.ingest(Sighting(Kind.AP, "00:1a:1e:77:30:01", c.t, -50, name="Cafe", security="WPA2"))
    e.ingest(Sighting(Kind.AP, "02:13:37:be:ef:01", c.t, -45, name="Cafe", security="OPEN"))
    e.tick()
    assert "twin/Cafe" in e.alerts


def test_wpa2_wpa3_mix_is_not_a_twin():
    e, c = make()
    e.ingest(Sighting(Kind.AP, "00:00:00:00:00:01", c.t, -50, name="Corp", security="WPA2"))
    e.ingest(Sighting(Kind.AP, "00:00:00:00:00:02", c.t, -50, name="Corp", security="WPA3"))
    e.tick()
    assert not e.alerts


def test_trusted_network_new_bssid():
    e, c = make()
    e.ingest(Sighting(Kind.AP, "00:00:00:00:00:01", c.t, -50, name="Home", security="WPA2"))
    e.trust_ssid("Home")
    e.ingest(Sighting(Kind.AP, "00:00:00:00:00:99", c.t, -50, name="Home", security="WPA2"))
    e.tick()
    assert e.alerts["trusted/Home"].macs == ["00:00:00:00:00:99"]


def test_deauth_burst():
    e, c = make()
    for _ in range(25):
        e.ingest(Deauth(c.t, "aa:aa:aa:aa:aa:aa", "ff:ff:ff:ff:ff:ff", "aa:aa:aa:aa:aa:aa"))
    e.tick()
    assert "deauth/aa:aa:aa:aa:aa:aa" in e.alerts


def test_follower_across_three_places_then_mine_clears():
    e, c = make()
    tag = "e1:5c:4e:a9:07:3d"
    for prefix in ("10:10:10", "20:20:20", "30:30:30"):
        c.t += 100  # move on: old APs fall out of the window
        for _ in range(2):  # stays long enough to count
            c.t += 1
            aps(e, c, prefix)
            e.ingest(Sighting(Kind.BLE, tag, c.t, -60, tracker="Apple Find My", tracker_state="separated"))
            e.tick()
    assert len(e.places.places) == 3
    assert e.alerts[f"follow/{tag}"].severity.value == "high"
    assert f"tracker/{tag}" in e.alerts  # also lingered > 60 s

    e.set_mine(f"ble/{tag}", True)
    e.tick()
    assert not any(tag in a.macs for a in e.alerts.values())


def test_near_owner_tracker_is_quiet():
    e, c = make()
    for _ in range(5):
        c.t += 30
        e.ingest(Sighting(Kind.BLE, "11:22:33:44:55:66", c.t, -60, tracker="Apple Find My",
                          tracker_state="near-owner"))
        e.tick()
    assert not e.alerts


def test_dismiss_sticks():
    e, c = make()
    e.ingest(Sighting(Kind.AP, "00:00:00:00:00:01", c.t, -50, name="Cafe", security="WPA2"))
    e.ingest(Sighting(Kind.AP, "00:00:00:00:00:02", c.t, -50, name="Cafe", security="OPEN"))
    e.tick()
    e.dismiss("twin/Cafe")
    e.tick()
    assert "twin/Cafe" not in e.alerts


def test_store_roundtrip(tmp_path):
    db = tmp_path / "r.db"
    e = Engine(Settings(), Store(db))
    e.ingest(Sighting(Kind.BLE, "11:22:33:44:55:66", 5.0, -60, name="Watch"))
    e.devices["ble/11:22:33:44:55:66"].mine = True
    e.tick(now=6.0)
    e2 = Engine(Settings(), Store(db))
    d = e2.devices["ble/11:22:33:44:55:66"]
    assert d.mine and d.names == {"Watch"}


def test_api(tmp_path):
    from fastapi.testclient import TestClient
    from rfradar.server import create_app

    e, c = make()
    e.ingest(Sighting(Kind.AP, "00:00:00:00:00:01", c.t, -50, name="Cafe", security="WPA2"))
    e.ingest(Sighting(Kind.AP, "00:00:00:00:00:02", c.t, -50, name="Cafe", security="OPEN"))
    e.tick()
    client = TestClient(create_app(e))
    st = client.get("/api/state").json()
    assert st["alerts"][0]["key"] == "twin/Cafe"
    assert client.post("/api/alerts/twin%2FCafe/dismiss").json()["ok"]
    assert client.get("/api/state").json()["alerts"] == []
    assert client.get("/").status_code == 200


def test_walking_between_places_does_not_merge_them():
    """Regression: a mixed A+B fingerprint mid-walk must not let A swallow B."""
    pt = PlaceTracker(0.35, 3)
    a = {f"a{i}" for i in range(6)}
    b = {f"b{i}" for i in range(6)}
    home = pt.locate(a, 0)
    pt.locate(set(list(a)[:4]) | set(list(b)[:2]), 1)   # leaving A, first bits of B
    pt.locate(set(list(a)[:2]) | set(list(b)[:4]), 2)   # mostly B now
    cafe = pt.locate(b, 3)
    assert cafe != home
    assert pt.locate(a, 4) == home


def test_passer_by_does_not_count_at_a_place():
    e, c = make()
    aps(e, c, "10:10:10")
    e.ingest(Sighting(Kind.BLE, "11:22:33:44:55:66", c.t, -70))
    e.tick()  # heard for a single tick only
    assert e.devices["ble/11:22:33:44:55:66"].places == set()
