"""Figuring out "where am I?" from the Wi-Fi networks around you.

Each tick we take the set of access points heard recently (the *fingerprint*)
and compare it with every place we already know using Jaccard similarity:

    similarity = |shared APs| / |all APs in either set|

1.0 means identical surroundings, 0.0 means nothing in common. Above the
threshold it's a place we know; otherwise it's somewhere new.
"""

from __future__ import annotations

from .models import Place

FINGERPRINT_CAP = 60  # keep fingerprints bounded in busy areas
# Only *learn* new APs into a place when we're very sure we're there. Learning on
# a weak match lets a place "snowball": while you walk from A to B the mixed
# fingerprint matches A, A absorbs B's networks, and B never becomes its own place.
LEARN_AT = 0.6


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class PlaceTracker:
    def __init__(self, match: float, min_aps: int):
        self.match = match
        self.min_aps = min_aps
        self.places: dict[int, Place] = {}
        self.current: int | None = None

    def locate(self, fingerprint: set[str], now: float) -> int | None:
        if len(fingerprint) < self.min_aps:
            self.current = None
            return None

        best_id, best_score = None, 0.0
        for place in self.places.values():
            score = jaccard(fingerprint, place.fingerprint)
            if score > best_score:
                best_id, best_score = place.id, score

        if best_id is not None and best_score >= self.match:
            place = self.places[best_id]
            # Learn: new APs at a known place get added (bounded).
            merged = place.fingerprint | fingerprint
            if best_score >= LEARN_AT and len(merged) <= FINGERPRINT_CAP:
                place.fingerprint = merged
            place.last_seen = now
        else:
            new_id = max(self.places, default=0) + 1
            place = Place(new_id, f"Place {new_id}", set(fingerprint), now, now)
            self.places[new_id] = place

        self.current = place.id
        return place.id
