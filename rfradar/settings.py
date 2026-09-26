"""Tunable thresholds, in one place.

Real-world defaults are deliberately conservative (few false alarms). The demo
preset shrinks every time window so the simulated scenario plays out in a
couple of minutes instead of a day.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Settings:
    tick_s: float = 30.0            # how often we recompute places + alerts
    place_window_s: float = 120.0   # APs heard within this window define "where am I now"
    place_min_aps: int = 3          # fewer visible APs than this = location unknown
    place_match: float = 0.35       # Jaccard similarity needed to call it the same place
    place_min_rssi: int = -85       # ignore very faint APs when fingerprinting
    presence_ticks: int = 0         # ticks heard at a place before it counts (0 = auto, see below)
    follow_places: int = 3          # seen at this many distinct places => "following you"
    follow_watch_places: int = 2    # ...this many => worth watching
    tracker_linger_s: float = 15 * 60  # separated tracker around you this long => alert
    deauth_window_s: float = 10.0
    deauth_burst: int = 20          # this many kick-off frames within the window => alert
    active_s: float = 300.0         # a device counts as "around now" if heard this recently
    retention_days: float = 7.0     # forget ordinary devices after this long

    @property
    def min_presence_ticks(self) -> int:
        """How long a device must be heard at a place before we say it was *there*.

        Auto = a bit longer than the fingerprint window, because for about one
        window after you arrive somewhere we still think you're at the old place.
        With real defaults that's ~3 minutes — also long enough that a stranger's
        phone walking past doesn't count.
        """
        if self.presence_ticks:
            return self.presence_ticks
        return int(self.place_window_s // self.tick_s) + 2

    @classmethod
    def demo(cls) -> "Settings":
        return cls(
            tick_s=3.0,
            place_window_s=8.0,
            follow_places=3,
            tracker_linger_s=40.0,
            active_s=20.0,
        )
