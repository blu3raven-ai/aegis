"""Circuit breaker for the Argus connector.

Protects Aegis from cascading failures when the Argus remote is degraded.
Three states follow the classic pattern:
  closed    → normal operation, failures counted
  open      → fast-fail for recovery_timeout_seconds after threshold is breached
  half_open → one probe call after timeout; success resets to closed, failure re-opens
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


class CircuitOpenError(Exception):
    """Raised when a call is attempted while the circuit is open."""


@dataclass
class CircuitState:
    status: str  # 'closed' | 'open' | 'half_open'
    failure_count: int
    last_failure_at: datetime | None
    opened_at: datetime | None


class CircuitBreaker:
    """Thread-safe circuit breaker.

    Args:
        failure_threshold: Consecutive failures before the circuit opens.
        recovery_timeout_seconds: Seconds to wait in open state before probing.
        half_open_max_calls: Probe calls allowed in half_open before a decision.
        on_state_change: Optional callable notified with new status string on
            every transition (used by metrics to update the state gauge).
    """

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        recovery_timeout_seconds: int = 30,
        half_open_max_calls: int = 1,
        on_state_change: Callable[[str], None] | None = None,
    ) -> None:
        self._state = CircuitState(
            status="closed",
            failure_count=0,
            last_failure_at=None,
            opened_at=None,
        )
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout_seconds
        self._half_open_max = half_open_max_calls
        self._half_open_calls = 0
        self._lock = threading.Lock()
        self._on_state_change = on_state_change

    @property
    def state(self) -> CircuitState:
        with self._lock:
            return CircuitState(
                status=self._state.status,
                failure_count=self._state.failure_count,
                last_failure_at=self._state.last_failure_at,
                opened_at=self._state.opened_at,
            )

    def is_open(self) -> bool:
        """Return True if the circuit should block the call.

        Advances open → half_open once the recovery timeout has elapsed.
        """
        with self._lock:
            if self._state.status == "closed":
                return False
            if self._state.status == "open":
                if self._state.opened_at is not None:
                    elapsed = (datetime.now(timezone.utc) - self._state.opened_at).total_seconds()
                    if elapsed >= self._recovery_timeout:
                        self._transition("half_open")
                        # Count this first probe before allowing it through
                        self._half_open_calls = 1
                        return False
                return True
            # half_open: check available probe slots then consume one
            if self._half_open_calls >= self._half_open_max:
                return True
            self._half_open_calls += 1
            return False



    def record_success(self) -> None:
        """Called after a successful remote call. Resets the circuit to closed."""
        with self._lock:
            if self._state.status != "closed":
                self._transition("closed")
            self._state.failure_count = 0
            self._half_open_calls = 0

    def record_failure(self) -> None:
        """Called after a failed remote call. May trip the circuit to open."""
        with self._lock:
            self._state.failure_count += 1
            self._state.last_failure_at = datetime.now(timezone.utc)
            if self._state.status == "half_open":
                # Probe failed — reopen immediately
                self._transition("open")
                self._state.opened_at = datetime.now(timezone.utc)
                self._half_open_calls = 0
            elif (
                self._state.status == "closed"
                and self._state.failure_count >= self._failure_threshold
            ):
                self._transition("open")
                self._state.opened_at = datetime.now(timezone.utc)

    def call(self, fn: Callable, *args, **kwargs):
        """Wrap fn with circuit-breaker logic.

        Raises CircuitOpenError when the circuit is open so callers can route
        to fallbacks without attempting the remote call.
        """
        if self.is_open():
            raise CircuitOpenError(
                f"Circuit is open (status={self._state.status}); skipping remote call."
            )
        try:
            result = fn(*args, **kwargs)
            self.record_success()
            return result
        except Exception:
            self.record_failure()
            raise

    # ── private ───────────────────────────────────────────────────────────────

    def _transition(self, new_status: str) -> None:
        """Mutate state status and notify the state-change hook."""
        self._state.status = new_status
        if self._on_state_change is not None:
            try:
                self._on_state_change(new_status)
            except Exception:
                pass  # metrics hook must never crash the breaker
