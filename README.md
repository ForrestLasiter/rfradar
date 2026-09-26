# RF Radar

Passive, **listen-only** wireless awareness for a Linux laptop. It answers three questions:

1. **What's around me?** Wi-Fi networks, Wi-Fi devices, Bluetooth devices.
2. **Is anything following me?** Devices, especially AirTags, Tiles and SmartTags, that keep turning up at *different* places you go.
3. **Is a hotspot lying?** An evil twin (the same network name broadcast open *and* secured), an unknown access point using your trusted network's name, a rogue that answers to many names, or someone flooding "get off this network" frames.

Everything runs and stays on your laptop. The dashboard is served on `127.0.0.1` only.

## Quick start

```bash
# On Kali (PEP 668 means pipx rather than pip):
pipx install "./rfradar[all]"

rfradar doctor                 # what can this machine do?
rfradar run --demo             # simulated walk: home → coffee shop → office → home
rfradar run --scan --ble       # real: built-in Wi-Fi + Bluetooth, no root, no Alfa needed
```

Full capture with a monitor-mode adapter (e.g. an Alfa). The built-in card stays on NetworkManager, so your internet keeps working:

```bash
sudo "$(which rfradar)" monitor wlan1 on
sudo "$(which rfradar)" run --wifi wlan1 --ble
sudo "$(which rfradar)" monitor wlan1 off     # give the card back to NetworkManager
```

(`sudo "$(which rfradar)"` is needed because sudo's PATH doesn't include `~/.local/bin`.)

| Source | Needs | Sees |
|---|---|---|
| `--scan` | built-in Wi-Fi, NetworkManager | access points → places, evil twins, trusted-network check |
| `--ble` | built-in Bluetooth (BlueZ) | Bluetooth devices, trackers, followers |
| `--wifi IFACE` | monitor-mode adapter, root | + Wi-Fi devices, the networks they probe for, deauth floods, rogue multi-name APs |
| `--demo` | nothing | a scripted scenario that triggers every alert |

## Using the dashboard

- **Mine**: mark your own phone, watch and earbuds so they never raise "following you" alerts.
- **Trust**: on the Wi-Fi tab, trust your home or work network. RF Radar records its access points, and any *new* access point that shows up using that name triggers an alert.
- **Places**: rename "Place 1" to "Home" and so on. Places are recognised by the Wi-Fi networks visible there, because the laptop has no GPS.
- **Pause live updates**: freezes the page so you can read or click without it redrawing.

## How it decides

See [docs/DESIGN.md](docs/DESIGN.md). In short:

- **Place:** the set of access points heard recently is compared (Jaccard similarity) with the fingerprints of places it already knows.
- **Follower:** heard for a few minutes at 3 or more *different* places. Randomised-address phones are noted as possibly coincidental.
- **Tracker:** a separated Find My, Tile, SmartTag, Chipolo or Google tag that has stayed near you for 15 minutes or more.

## Development

```bash
pip install -e ".[dev]"
pytest
rfradar run --demo --demo-dwell 30
```

Licence: MIT.
