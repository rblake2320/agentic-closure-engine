"""Service clock. Runtime timestamps come from here, never from a request or CLI argument."""

import threading
import time

from ..protocol import timestamp


class SystemClock:
    """UTC wall clock in milliseconds, made non-decreasing within one process."""

    def __init__(self):
        self._last = 0
        self._lock = threading.Lock()

    def now_ms(self):
        with self._lock:
            self._last = max(self._last, time.time_ns() // 1_000_000)
            return self._last

    def now(self):
        return timestamp(self.now_ms())
