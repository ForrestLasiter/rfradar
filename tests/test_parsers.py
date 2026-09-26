"""Frame / advertisement / nmcli parsing — no radio needed."""

from types import SimpleNamespace

from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11EltRSN, Dot11ProbeReq, RadioTap,
)

from rfradar.models import Deauth, Kind
from rfradar.oui import is_multicast, is_randomized
from rfradar.signatures import classify_ble
from rfradar.sources.ble import sighting_from_adv
from rfradar.sources.wifi_scan import parse_nmcli
from rfradar.wifi_parse import parse_frame

AP = "a4:2b:b0:10:00:01"


def beacon(ssid, secure=True, ch=6):
    cap = "ESS+privacy" if secure else "ESS"
    pkt = (RadioTap(dBm_AntSignal=-47, present="dBm_AntSignal") /
           Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=AP, addr3=AP) /
           Dot11Beacon(cap=cap) / Dot11Elt(ID="SSID", info=ssid) /
           Dot11Elt(ID="DSset", info=bytes([ch])))
    if secure:
        pkt = pkt / Dot11EltRSN()
    return RadioTap(bytes(pkt))  # round-trip through bytes, like a real capture


def test_beacon_secure():
    [s] = parse_frame(beacon("Home-5G"), 1.0)
    assert s.kind == Kind.AP and s.mac == AP and s.name == "Home-5G"
    assert s.channel == 6 and s.security == "WPA2" and s.rssi == -47


def test_beacon_open_and_hidden():
    [s] = parse_frame(beacon("Cafe", secure=False), 1.0)
    assert s.security == "OPEN"
    [h] = parse_frame(beacon(""), 1.0)
    assert h.name is None


def test_probe_request():
    pkt = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2="7a:11:22:33:44:55",
                addr3="ff:ff:ff:ff:ff:ff") / Dot11ProbeReq() / Dot11Elt(ID="SSID", info="HomeNet")
    [s] = parse_frame(pkt, 1.0)
    assert s.kind == Kind.CLIENT and s.probed_ssid == "HomeNet"


def test_deauth_and_data():
    d = Dot11(type=0, subtype=12, addr1="11:22:33:44:55:66", addr2=AP, addr3=AP) / Dot11Deauth(reason=7)
    [e] = parse_frame(d, 1.0)
    assert isinstance(e, Deauth) and e.bssid == AP
    data = Dot11(type=2, subtype=0, FCfield=0x1, addr1=AP, addr2="b8:27:eb:5a:11:02", addr3=AP)
    [c] = parse_frame(data, 1.0)
    assert c.kind == Kind.CLIENT and c.mac == "b8:27:eb:5a:11:02" and c.bssid == AP


def test_mac_bits():
    assert is_randomized("7a:11:22:33:44:55")
    assert not is_randomized("a4:2b:b0:10:00:01")
    assert is_multicast("ff:ff:ff:ff:ff:ff") and is_multicast("01:00:5e:00:00:01")


def test_trackers():
    airtag = classify_ble({0x004C: bytes([0x12, 0x19, 0x10]) + bytes(24)})
    assert airtag.state == "separated" and "Apple" in airtag.label
    assert classify_ble({0x004C: bytes([0x12, 0x02, 0x00, 0x01])}).state == "near-owner"
    assert classify_ble({0x004C: bytes([0x10, 0x05, 0x01])}) is None  # ordinary iPhone chatter
    assert classify_ble(service_uuids=["0000feed-0000-1000-8000-00805f9b34fb"]).label == "Tile"
    assert classify_ble(service_data={"0000fd5a-0000-1000-8000-00805f9b34fb": b"\x01"}).label == "Samsung SmartTag"
    assert classify_ble() is None


def test_ble_adv_conversion():
    adv = SimpleNamespace(manufacturer_data={0x004C: bytes([0x12, 0x19]) + bytes(25)}, service_data={},
                          service_uuids=[], local_name=None, rssi=-60)
    s = sighting_from_adv("E1:5C:4E:A9:07:3D", adv, 1.0)
    assert s.mac == "e1:5c:4e:a9:07:3d" and s.vendor == "Apple" and s.tracker_state == "separated"


def test_nmcli():
    out = ("A4\\:2B\\:B0\\:10\\:00\\:01:Home\\:5G:36:84:WPA3\n"
           "02\\:13\\:37\\:BE\\:EF\\:01:BeanThere_Guest:6:90:\n"
           "garbage line\n")
    a, b = parse_nmcli(out, 1.0)
    assert a.mac == "a4:2b:b0:10:00:01" and a.name == "Home:5G" and a.security == "WPA3" and a.rssi == -58
    assert b.security == "OPEN"
