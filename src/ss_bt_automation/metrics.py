"""In-process counters for observability."""

from __future__ import annotations

import threading
from typing import Any


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}

    def inc(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + value

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counters)

    def as_dict(self) -> dict[str, Any]:
        return {"counters": self.snapshot()}
