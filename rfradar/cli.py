"""Command line: `rfradar run`, `rfradar doctor`, `rfradar monitor`.

Examples
    rfradar run --demo                 # fake data, works anywhere — try this first
    rfradar run --scan --ble           # built-in Wi-Fi + Bluetooth, no root needed
    sudo rfradar monitor wlan1 on      # put the Alfa into monitor mode
    sudo rfradar run --wifi wlan1 --ble
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import platform
import shutil
import subprocess
import sys
import webbrowser

from . import __version__
from .settings import Settings
from .store import Store, default_db_path

DEFAULT_PORT = 8750


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def cmd_run(a: argparse.Namespace) -> int:
    import uvicorn

    from .engine import Engine
    from .server import create_app

    sources = []
    if a.demo:
        from .sources.sim import SimSource
        sources.append(SimSource(seconds_per_place=a.demo_dwell))
    if a.scan:
        from .sources.wifi_scan import WifiScanSource
        sources.append(WifiScanSource())
    if a.wifi:
        if not _is_root():
            print("Monitor-mode capture needs root: sudo rfradar run --wifi ...", file=sys.stderr)
            return 2
        from .sources.wifi_monitor import WifiMonitorSource
        sources.append(WifiMonitorSource(a.wifi, five_ghz=not a.no_5ghz))
    if a.ble:
        from .sources.ble import BleSource
        sources.append(BleSource())
    if not sources:
        print("Pick at least one source: --demo, --scan, --wifi IFACE, --ble  (see rfradar run -h)",
              file=sys.stderr)
        return 2

    settings = Settings.demo() if a.demo else Settings()
    # Demo data is fake, so it lives in memory only and never pollutes your real history.
    store = Store(None if a.demo else (a.db or default_db_path()))
    engine = Engine(settings, store)
    app = create_app(engine)

    url = f"http://127.0.0.1:{a.port}/"
    print(f"RF Radar {__version__} — dashboard at {url}  (Ctrl+C to stop)")
    for s in sources:
        print(f"  • {s.name}")

    async def main():
        config = uvicorn.Config(app, host="127.0.0.1", port=a.port, log_level="warning")
        server = uvicorn.Server(config)
        if not a.no_browser:
            asyncio.get_running_loop().call_later(1.0, webbrowser.open, url)
        runner = asyncio.create_task(engine.run(sources))
        try:
            await server.serve()
        finally:
            runner.cancel()
            engine.tick()  # final save

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    return 0


def cmd_doctor(a: argparse.Namespace) -> int:
    """Check what this machine can do, in plain language."""
    ok = lambda b: "OK  " if b else "--  "  # noqa: E731
    print(f"RF Radar {__version__} on {platform.system()} {platform.release()}\n")
    linux = platform.system() == "Linux"
    print(f"{ok(linux)} Linux (real radios are Linux-only; --demo works anywhere)")

    try:
        import scapy  # noqa: F401
        has_scapy = True
    except ImportError:
        has_scapy = False
    try:
        import bleak  # noqa: F401
        has_bleak = True
    except ImportError:
        has_bleak = False
    print(f"{ok(bool(shutil.which('nmcli')))} nmcli  → --scan (built-in Wi-Fi, no root)")
    print(f"{ok(has_bleak)} bleak  → --ble (pip install 'rfradar[ble]')")
    print(f"{ok(has_scapy)} scapy  → --wifi monitor capture (pip install 'rfradar[wifi]')")
    print(f"{ok(bool(shutil.which('iw')))} iw     → channel hopping / monitor mode")

    if linux and shutil.which("iw"):
        from .sources.wifi_monitor import iface_mode
        out = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
        ifaces = [l.split()[1] for l in out.splitlines() if l.strip().startswith("Interface ")]
        phys = subprocess.run(["iw", "list"], capture_output=True, text=True).stdout
        can_monitor = "* monitor" in phys
        print("\nWireless interfaces:")
        for i in ifaces:
            print(f"  {i:10} mode={iface_mode(i)}")
        print(f"\n{ok(can_monitor)} at least one card supports monitor mode")
        if not can_monitor or len(ifaces) < 2:
            print("    Tip: plug in an external adapter (e.g. Alfa) for --wifi; keep the built-in\n"
                  "    card on NetworkManager so your internet keeps working.")
    return 0


def cmd_monitor(a: argparse.Namespace) -> int:
    if not _is_root():
        print("Needs root: sudo rfradar monitor IFACE on|off", file=sys.stderr)
        return 2
    iface = a.iface
    # Tell NetworkManager to leave the card alone while it's in monitor mode,
    # otherwise NM fights us and flips it back.
    nm = "no" if a.state == "on" else "yes"
    mode = "monitor" if a.state == "on" else "managed"
    steps = [
        ["nmcli", "device", "set", iface, "managed", nm],
        ["ip", "link", "set", iface, "down"],
        ["iw", "dev", iface, "set", "type", mode],
        ["ip", "link", "set", iface, "up"],
    ]
    if a.state == "off":
        steps = steps[1:] + steps[:1]  # hand back to NM last
    for cmd in steps:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0 and cmd[0] != "nmcli":
            print(f"failed: {' '.join(cmd)}\n{r.stderr.strip()}", file=sys.stderr)
            return 1
    print(f"{iface} is now in {mode} mode.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="rfradar", description="Passive, listen-only wireless awareness.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="start listening and open the dashboard")
    r.add_argument("--demo", action="store_true", help="simulated data (no radio needed)")
    r.add_argument("--demo-dwell", type=float, default=45.0, help="demo: seconds at each place")
    r.add_argument("--scan", action="store_true", help="built-in Wi-Fi via NetworkManager scans")
    r.add_argument("--wifi", metavar="IFACE", help="monitor-mode interface for full capture (root)")
    r.add_argument("--no-5ghz", action="store_true", help="only hop 2.4 GHz channels")
    r.add_argument("--ble", action="store_true", help="Bluetooth LE scanning")
    r.add_argument("--port", type=int, default=DEFAULT_PORT)
    r.add_argument("--db", help=f"database path (default {default_db_path()})")
    r.add_argument("--no-browser", action="store_true")
    r.set_defaults(func=cmd_run)

    d = sub.add_parser("doctor", help="check which radios and tools are available")
    d.set_defaults(func=cmd_doctor)

    m = sub.add_parser("monitor", help="switch an interface into/out of monitor mode (root)")
    m.add_argument("iface")
    m.add_argument("state", choices=["on", "off"])
    m.set_defaults(func=cmd_monitor)

    a = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
