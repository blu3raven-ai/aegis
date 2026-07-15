"""Unit coverage for the Argus circuit breaker state machine.

Drives the closed → open → half_open → closed transitions directly. The
open → half_open advance is normally time-gated; tests use
``recovery_timeout_seconds=0`` so the elapsed check fires immediately instead
of sleeping, keeping the suite deterministic.
"""
from __future__ import annotations

import pytest

from src.argus.circuit_breaker import CircuitBreaker, CircuitOpenError


def test_starts_closed_and_allows_calls():
    cb = CircuitBreaker()
    assert cb.state.status == "closed"
    assert cb.is_open() is False


def test_failures_below_threshold_stay_closed():
    cb = CircuitBreaker(failure_threshold=3)
    cb.record_failure()
    cb.record_failure()
    assert cb.state.status == "closed"
    assert cb.state.failure_count == 2
    assert cb.is_open() is False


def test_threshold_breach_trips_open():
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=30)
    for _ in range(3):
        cb.record_failure()
    assert cb.state.status == "open"
    assert cb.state.opened_at is not None
    # Within the recovery window the circuit blocks calls.
    assert cb.is_open() is True


def test_open_advances_to_half_open_after_recovery_timeout():
    # recovery_timeout=0 means the elapsed check passes on the first poll.
    cb = CircuitBreaker(failure_threshold=1, recovery_timeout_seconds=0)
    cb.record_failure()
    assert cb.state.status == "open"
    # First poll after timeout transitions to half_open and lets one probe through.
    assert cb.is_open() is False
    assert cb.state.status == "half_open"


def test_half_open_success_closes_circuit_and_resets_count():
    cb = CircuitBreaker(failure_threshold=1, recovery_timeout_seconds=0)
    cb.record_failure()
    cb.is_open()  # advance to half_open, consume the probe slot
    cb.record_success()
    assert cb.state.status == "closed"
    assert cb.state.failure_count == 0
    assert cb.is_open() is False


def test_half_open_failure_reopens_immediately():
    cb = CircuitBreaker(failure_threshold=1, recovery_timeout_seconds=0)
    cb.record_failure()  # -> open
    cb.is_open()  # -> half_open
    assert cb.state.status == "half_open"
    cb.record_failure()  # probe failed -> reopen
    assert cb.state.status == "open"
    assert cb.state.opened_at is not None


def test_half_open_allows_only_max_probe_calls():
    cb = CircuitBreaker(
        failure_threshold=1, recovery_timeout_seconds=0, half_open_max_calls=1
    )
    cb.record_failure()
    # First poll: transition to half_open, first probe allowed.
    assert cb.is_open() is False
    # Second poll while still half_open: probe budget exhausted, block.
    assert cb.is_open() is True


def test_call_raises_circuit_open_when_open():
    cb = CircuitBreaker(failure_threshold=1, recovery_timeout_seconds=30)
    cb.record_failure()
    with pytest.raises(CircuitOpenError):
        cb.call(lambda: "should not run")


def test_call_success_records_success_and_returns_result():
    cb = CircuitBreaker(failure_threshold=2)
    cb.record_failure()  # one prior failure
    out = cb.call(lambda x: x * 2, 21)
    assert out == 42
    # Success resets the failure count.
    assert cb.state.failure_count == 0


def test_call_failure_records_and_reraises():
    cb = CircuitBreaker(failure_threshold=5)

    def boom():
        raise ValueError("remote down")

    with pytest.raises(ValueError, match="remote down"):
        cb.call(boom)
    assert cb.state.failure_count == 1


def test_state_property_returns_a_copy():
    cb = CircuitBreaker()
    snap = cb.state
    snap.failure_count = 999
    # Mutating the snapshot must not bleed into the breaker's own state.
    assert cb.state.failure_count == 0


def test_on_state_change_hook_fires_on_transition():
    seen: list[str] = []
    cb = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout_seconds=0,
        on_state_change=seen.append,
    )
    cb.record_failure()  # closed -> open
    cb.is_open()  # open -> half_open
    cb.record_success()  # half_open -> closed
    assert seen == ["open", "half_open", "closed"]


def test_on_state_change_hook_exception_never_crashes_breaker():
    def boom(_status: str) -> None:
        raise RuntimeError("metrics backend down")

    cb = CircuitBreaker(failure_threshold=1, on_state_change=boom)
    # Must not propagate the hook's exception.
    cb.record_failure()
    assert cb.state.status == "open"
