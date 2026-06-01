# runner/graceful_drain.py
"""Graceful drain on SIGTERM / SIGINT.

Flow on signal receipt:
  1. _draining event is set — no new jobs are accepted
  2. Caller calls wait_for_drain() which blocks until in-flight count reaches 0
     or drain_timeout seconds elapse
  3. If timeout is hit, the caller should log a warning and exit anyway
"""
from __future__ import annotations

import signal
import threading
import time


class GracefulDrainManager:
    """Coordinates graceful shutdown on SIGTERM.

    Callers wrap job execution with track_job_start / track_job_end and poll
    is_draining() before accepting new work.
    """

    def __init__(self, drain_timeout: int = 300) -> None:
        self._draining = threading.Event()
        self._in_flight_count = 0
        self._lock = threading.Lock()
        self._drain_timeout = drain_timeout

    def install_handler(self) -> None:
        """Register SIGTERM and SIGINT handlers. Safe to call only from main thread."""
        try:
            signal.signal(signal.SIGTERM, self._on_signal)
            signal.signal(signal.SIGINT, self._on_signal)
        except (OSError, ValueError):
            # Not in main thread or platform doesn't support it
            pass

    def _on_signal(self, signum, frame) -> None:  # noqa: ARG002
        self._draining.set()

    def is_draining(self) -> bool:
        """Return True once a shutdown signal has been received."""
        return self._draining.is_set()

    def trigger_drain(self) -> None:
        """Programmatically trigger drain (useful in tests and for stop() integration)."""
        self._draining.set()

    def track_job_start(self) -> None:
        """Increment the in-flight counter before dispatching a job."""
        with self._lock:
            self._in_flight_count += 1

    def track_job_end(self) -> None:
        """Decrement the in-flight counter when a job finishes (success or failure)."""
        with self._lock:
            self._in_flight_count = max(0, self._in_flight_count - 1)

    @property
    def in_flight_count(self) -> int:
        with self._lock:
            return self._in_flight_count

    def wait_for_drain(self) -> bool:
        """Block until in-flight jobs reach 0 or drain_timeout elapses.

        Returns True if drained cleanly, False if timeout was hit.
        """
        deadline = time.monotonic() + self._drain_timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._in_flight_count == 0:
                    return True
            time.sleep(0.1)
        # One final check after the loop exits
        with self._lock:
            return self._in_flight_count == 0
