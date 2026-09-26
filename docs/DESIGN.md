# RF Radar — design

## Ground rules

1. **Listen-only.** No code path transmits Wi-Fi frames: no deauth, no injection, no probing, and no `sendp`. We read frame *headers* (addresses, network names, frame types) and never payloads.
   - One honest exception is noted in `sources/ble.py`. bleak's default BLE scan is *active*: it sends a scan request to read a device's name. It never connects or pairs. A truly passive BLE mode is on the roadmap.
2. **Local-only.** A SQLite file under `~/.local/share/rfradar/`, a dashboard bound to 127.0.0.1, and no telemetry.
3. **Forgetful.** Ordinary devices are purged after 7 days (`retention_days`). Devices you mark "mine", places and trusted networks are kept. Demo mode uses an in-memory database only.
4. **Defensive purpose.** It detects things aimed at *you* (tracking, rogue hotspots). Capturing broadcast management frames is what every Wi-Fi scanner does, but it's still other people's device metadata, so keep it on your machine.

## Architecture

```
sources/            each yields Sighting | Deauth forever (async generator)
  sim.py            scripted scenario — no radio
  wifi_scan.py      nmcli scans on the built-in card (APs only, no root)
  wifi_monitor.py   scapy AsyncSniffer + channel-hopper thread (root, monitor mode)
  ble.py            bleak / BlueZ advertisements
      │
      ▼
engine.py           ingest(): fold sightings into Device records
                    tick():   fingerprint → Place, run analyzers, persist
      │
      ├── places.py      Jaccard place recognition
      ├── analyzers.py   evil_twins / deauth_bursts / trackers / followers  (pure functions)
      ├── signatures.py  BLE tracker recognition                            (pure function)
      ├── wifi_parse.py  802.11 frame → Sighting                            (pure function)
      └── store.py       SQLite (devices as JSON blobs, places, trusted SSIDs)
      │
      ▼
server.py + web/    FastAPI JSON API + static, accessible (WCAG 2.1 AA) dashboard
```

A single asyncio loop runs everything, so there are no locks. The scapy sniffer runs in its own thread and hands frames over with `loop.call_soon_threadsafe`.

## Detection rules

| Rule | Fires when | Severity |
|---|---|---|
| Evil twin | Same SSID seen both OPEN/WEP and encrypted (a WPA2/WPA3 mix is ignored) | high |
| Trusted-network impostor | A trusted SSID from a BSSID not recorded when you trusted it | medium |
| Karma rogue | One open BSSID broadcasting 4 or more SSIDs | medium |
| Deauth flood | 20 or more deauth/disassoc frames within 10 s for one BSSID (monitor mode only) | high |
| Lingering tracker | A separated/unknown-state tracker, heard continuously for 15 minutes or more | medium |
| Follower (watch) | A tracker at 2 of your places | medium |
| Follower | Any non-AP device at 3 or more of your places | high |

**Presence rule (important).** A device only counts as *at* a place after being heard there for `min_presence_ticks` ticks, which is about one fingerprint window plus a margin (≈3 minutes with real settings). There are two reasons. For about one window after you arrive somewhere, the fingerprint still matches the old place. And a stranger's phone walking past shouldn't count. The demo run exposed both problems before this rule was added; `test_passer_by_does_not_count_at_a_place` covers it.

**Place learning.** A known place only absorbs new APs when similarity is 0.6 or higher (`LEARN_AT`). Learning on weaker matches let place A "snowball" into place B while walking between them.

## Tracker signatures (`signatures.py`)

| Tracker | Signature | Confidence |
|---|---|---|
| Apple Find My | Apple mfr data (0x004C), type 0x12; payload length 25 or more = *separated* | high |
| Samsung SmartTag | service data 0xFD5A | high |
| Tile | service 0xFEED / 0xFEEC | high |
| Chipolo | service 0xFE33 | medium, verify with a real tag |
| Google FMDN | Eddystone 0xFEAA, frame 0x40/0x41 | medium, verify with a real tag |

## Roadmap

- **Phase 1 (this):** core engine, 4 sources, 7 rules, dashboard, 20 tests, demo.
- **Phase 2:**
  - First run on the real T490s; tune thresholds on real data.
  - Truly passive BLE (BlueZ advertisement monitor).
  - Desktop notifications (`notify-send`) for high alerts.
  - Add as a `provision.sh` module in the Kali kit.
- **Phase 3:**
  - Place history timeline ("this tracker was at Home 09:10, Café 12:30…").
  - Export an incident report (for police, if a tracker is found).
  - Umbra integration: a "go dark" profile could show RF Radar's view.
- **Maybe:**
  - A Kismet source (reuse its capture engine).
  - GPS via a USB puck or phone for real coordinates.
  - An SDR source (433 MHz / sub-GHz trackers).
