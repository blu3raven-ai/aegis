"""Tests for CircuitBreaker — state transitions, threshold trips, half-open behavior."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.argus.circuit_breaker import CircuitBreaker, CircuitOpenError


def _make_breaker(**kwargs) -> CircuitBreaker:
    defaults = dict(failure_threshold=3, recovery_timeout_seconds=30, half_open_max_calls=1)
    defaults.update(kwargs)
    return CircuitBreaker(**defaults)


# ── initial state ─────────────────────────────────────────────────────────────


def test_initial_state_is_closed():
    cb = _make_breaker()
    assert cb.state.status == "closed"
    assert cb.state.failure_count == 0


def test_closed_circuit_is_not_open():
    cb = _make_breaker()
    assert cb.is_open() is False


# ── transitions closed → open ──────────────────────────────────────────────────


def test_circuit_opens_after_threshold_failures():
    cb = _make_breaker(failure_threshold=3)
    for _ in range(3):
        cb.record_failure()
    assert cb.state.status == "open"


def test_circuit_does_not_open_before_threshold():
    cb = _make_breaker(failure_threshold=3)
    cb.record_failure()
    cb.record_failure()
    assert cb.state.status == "closed"


def test_open_circuit_is_open():
    cb = _make_breaker(failure_threshold=1)
    cb.record_failure()
    assert cb.is_open() is True


def test_opened_at_is_set_when_tripped():
    cb = _make_breaker(failure_threshold=1)
    before = datetime.now(timezone.utc)
    cb.record_failure()
    after = datetime.now(timezone.utc)
    assert cb.state.opened_at is not None
    assert before <= cb.state.opened_at <= after


# ── open → half_open after timeout ────────────────────────────────────────────


def test_open_circuit_transitions_to_half_open_after_recovery_timeout():
    cb = _make_breaker(failure_threshold=1, recovery_timeout_seconds=30)
    cb.record_failure()
    assert cb.state.status == "open"

    past = datetime.now(timezone.utc) - timedelta(seconds=31)
    with cb._lock:
        cb._state.opened_at = past

    # is_open() advances the state and should return False (allowing the probe)
    assert cb.is_open() is False
    assert cb.state.status == "half_open"


def test_open_circuit_stays_open_before_timeout():
    cb = _make_breaker(failure_threshold=1, recovery_timeout_seconds=30)
    cb.record_failure()

    # opened_at is recent — should still be open
    assert cb.is_open() is True


# ── half_open behavior ────────────────────────────────────────────────────────


def test_half_open_success_closes_circuit():
    cb = _make_breaker(failure_threshold=1, recovery_timeout_seconds=30)
    cb.record_failure()

    past = datetime.now(timezone.utc) - timedelta(seconds=31)
    with cb._lock:
        cb._state.opened_at = past

    cb.is_open()  # advances to half_open
    cb.record_success()
    assert cb.state.status == "closed"
    assert cb.state.failure_count == 0


def test_half_open_failure_reopens_circuit():
    cb = _make_breaker(failure_threshold=1, recovery_timeout_seconds=30)
    cb.record_failure()

    past = datetime.now(timezone.utc) - timedelta(seconds=31)
    with cb._lock:
        cb._state.opened_at = past

    cb.is_open()  # advances to half_open
    cb.record_failure()
    assert cb.state.status == "open"


def test_half_open_blocks_calls_beyond_max():
    cb = _make_breaker(failure_threshold=1, recovery_timeout_seconds=30, half_open_max_calls=1)
    cb.record_failure()

    past = datetime.now(timezone.utc) - timedelta(seconds=31)
    with cb._lock:
        cb._state.opened_at = past

    # First call transitions to half_open and allows one probe
    assert cb.is_open() is False  # probe allowed
    # Second call: limit exceeded, blocked
    assert cb.is_open() is True


# ── success resets failure count ──────────────────────────────────────────────


def test_success_resets_failure_count():
    cb = _make_breaker(failure_threshold=5)
    for _ in range(4):
        cb.record_failure()
    cb.record_success()
    assert cb.state.failure_count == 0
    assert cb.state.status == "closed"


# ── call() wrapper ────────────────────────────────────────────────────────────


def test_call_raises_circuit_open_error_when_open():
    cb = _make_breaker(failure_threshold=1)
    cb.record_failure()

    with pytest.raises(CircuitOpenError):
        cb.call(lambda: "should not run")


def test_call_passes_through_return_value():
    cb = _make_breaker()
    result = cb.call(lambda: 42)
    assert result == 42


def test_call_records_success_on_clean_return():
    cb = _make_breaker(failure_threshold=5)
    for _ in range(4):
        cb.record_failure()
    cb.call(lambda: None)
    assert cb.state.failure_count == 0


def test_call_records_failure_and_reraises():
    cb = _make_breaker(failure_threshold=5)
    initial_count = cb.state.failure_count

    with pytest.raises(ValueError, match="boom"):
        cb.call(lambda: (_ for _ in ()).throw(ValueError("boom")))

    assert cb.state.failure_count == initial_count + 1


def test_call_passes_args_and_kwargs():
    cb = _make_breaker()
    result = cb.call(lambda a, b=0: a + b, 3, b=7)
    assert result == 10


# ── state change callback ─────────────────────────────────────────────────────


def test_on_state_change_called_on_open():
    callback = MagicMock()
    cb = _make_breaker(failure_threshold=1, on_state_change=callback)
    cb.record_failure()
    callback.assert_called_once_with("open")


def test_on_state_change_called_on_close():
    callback = MagicMock()
    cb = _make_breaker(failure_threshold=1, on_state_change=callback)
    cb.record_failure()
    callback.reset_mock()

    past = datetime.now(timezone.utc) - timedelta(seconds=31)
    with cb._lock:
        cb._state.opened_at = past
    cb.is_open()  # → half_open
    cb.record_success()

    # half_open → closed triggers callback
    assert any(call[0][0] == "closed" for call in callback.call_args_list)


def test_on_state_change_exception_does_not_crash_breaker():
    def bad_callback(status):
        raise RuntimeError("metrics unavailable")

    cb = _make_breaker(failure_threshold=1, on_state_change=bad_callback)
    # Must not raise
    cb.record_failure()
    assert cb.state.status == "open"
