"""What every data source looks like to the engine.

A source is anything with a ``stream()`` async generator that yields
``Sighting`` / ``Deauth`` objects forever. Adding a new radio (an SDR, a
Kismet feed...) means writing one more class like this — nothing else changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from ..models import Deauth, Sighting


class Source(ABC):
    name: str = "source"

    def __init__(self) -> None:
        self.status = "starting"

    @abstractmethod
    def stream(self) -> AsyncIterator[Sighting | Deauth]:
        """Yield observations forever (or raise to report a failure)."""
