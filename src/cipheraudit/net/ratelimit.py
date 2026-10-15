"""Per-target connection rate limiter (PRD X-2)."""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """Spaces new connections at least 1/rate seconds apart. Thread-safe."""

    def __init__(self, rate_per_second: float) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate must be positive")
        self._interval = 1.0 / rate_per_second
        self._next_allowed = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._next_allowed - now
            self._next_allowed = max(now, self._next_allowed) + self._interval
        if wait > 0:
            time.sleep(wait)
