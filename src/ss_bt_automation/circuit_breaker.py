"""Simple circuit breaker for external APIs."""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, TypeVar

T = TypeVar("T")


class CircuitOpen(Exception):
    """Raised when circuit is open and calls are short-circuited."""

    def __init__(self, message: str = "Circuit breaker is open") -> None:
        super().__init__(message)


class CircuitBreaker:
    def __init__(self, failure_threshold: int, cooldown_seconds: float) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown_seconds = cooldown_seconds
        self._failures = 0
        self._opened_at: float | None = None
        self._lock = threading.Lock()

    def _is_open(self) -> bool:
        if self._opened_at is None:
            return False
        if time.monotonic() - self._opened_at >= self.cooldown_seconds:
            return False
        return True

    def call(self, fn: Callable[[], T], /) -> T:
        with self._lock:
            if self._opened_at is not None and not self._is_open():
                self._opened_at = None
                self._failures = 0
            if self._is_open():
                raise CircuitOpen()

        try:
            result = fn()
        except Exception:
            with self._lock:
                self._failures += 1
                if self._failures >= self.failure_threshold:
                    self._opened_at = time.monotonic()
            raise

        with self._lock:
            self._failures = 0
            self._opened_at = None
        return result

    def state(self) -> dict[str, Any]:
        with self._lock:
            return {
                "failures": self._failures,
                "open": self._is_open(),
                "opened_at_monotonic": self._opened_at,
            }
