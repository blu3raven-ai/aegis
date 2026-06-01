"""Tests for ArgusConnector retry-with-backoff logic.

Verifies: retry on 5xx, no retry on 4xx, backoff between attempts, budget cap.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from src.argus.connector import (
    ArgusConnector,
    _ArgusHttpError,
    _ArgusNetworkError,
    _ArgusTimeoutError,
)

ENDPOINT = "https://argus.example.com"
API_KEY = "test-api-key-retry"


def _connector() -> ArgusConnector:
    return ArgusConnector(endpoint=ENDPOINT, api_key=API_KEY)


def _http_error(status: int) -> _ArgusHttpError:
    return _ArgusHttpError(f"HTTP {status}", status_code=status)


# ── retry on 5xx ─────────────────────────────────────────────────────────────


def test_score_finding_retries_on_503_then_succeeds():
    connector = _connector()
    attempts = []

    def flaky_post(path, body):
        attempts.append(1)
        if len(attempts) < 2:
            raise _http_error(503)
        return {"score": 77.0}

    with patch.object(connector, "_post", side_effect=flaky_post):
        with patch("time.sleep"):
            result = connector.score_finding({"severity": "high"})

    assert result.source == "argus"
    assert result.score == 77.0
    assert len(attempts) == 2


def test_score_finding_retries_up_to_max_attempts_on_5xx():
    connector = _connector()
    call_count = [0]

    def always_503(path, body):
        call_count[0] += 1
        raise _http_error(503)

    with patch.object(connector, "_post", side_effect=always_503):
        with patch("time.sleep"):
            result = connector.score_finding({"severity": "high"})

    # Max 4 attempts (1 + 3 backoffs)
    assert call_count[0] == 4
    # Falls back to heuristic after exhausting retries
    assert result.source == "heuristic"


def test_score_finding_retries_on_network_error():
    connector = _connector()
    attempts = [0]

    def flaky(path, body):
        attempts[0] += 1
        if attempts[0] < 3:
            raise _ArgusNetworkError("connection refused")
        return {"score": 60.0}

    with patch.object(connector, "_post", side_effect=flaky):
        with patch("time.sleep"):
            result = connector.score_finding({"severity": "medium"})

    assert result.source == "argus"
    assert attempts[0] == 3


def test_score_finding_retries_on_timeout_error():
    connector = _connector()
    attempts = [0]

    def flaky(path, body):
        attempts[0] += 1
        if attempts[0] == 1:
            raise _ArgusTimeoutError("timed out")
        return {"score": 55.0}

    with patch.object(connector, "_post", side_effect=flaky):
        with patch("time.sleep"):
            result = connector.score_finding({"severity": "medium"})

    assert result.source == "argus"
    assert attempts[0] == 2


# ── no retry on 4xx ──────────────────────────────────────────────────────────


def test_score_finding_does_not_retry_on_400():
    connector = _connector()
    call_count = [0]

    def bad_request(path, body):
        call_count[0] += 1
        raise _http_error(400)

    with patch.object(connector, "_post", side_effect=bad_request):
        with patch("time.sleep") as mock_sleep:
            result = connector.score_finding({"severity": "high"})

    assert call_count[0] == 1  # exactly one attempt
    mock_sleep.assert_not_called()
    assert result.source == "heuristic"


def test_score_finding_does_not_retry_on_401():
    connector = _connector()
    call_count = [0]

    def unauthorized(path, body):
        call_count[0] += 1
        raise _http_error(401)

    with patch.object(connector, "_post", side_effect=unauthorized):
        with patch("time.sleep") as mock_sleep:
            result = connector.score_finding({"severity": "low"})

    assert call_count[0] == 1
    mock_sleep.assert_not_called()
    assert result.source == "heuristic"


def test_score_finding_does_not_retry_on_422():
    connector = _connector()
    call_count = [0]

    def unprocessable(path, body):
        call_count[0] += 1
        raise _http_error(422)

    with patch.object(connector, "_post", side_effect=unprocessable):
        with patch("time.sleep") as mock_sleep:
            result = connector.score_finding({"severity": "medium"})

    assert call_count[0] == 1
    mock_sleep.assert_not_called()


# ── backoff progression ────────────────────────────────────────────────────────


def test_backoff_delays_increase_between_attempts():
    """Sleep durations follow the configured schedule."""
    connector = _connector()
    sleep_calls = []

    def always_fail(path, body):
        raise _http_error(503)

    with patch.object(connector, "_post", side_effect=always_fail):
        with patch("time.sleep", side_effect=lambda s: sleep_calls.append(s)):
            connector.score_finding({"severity": "high"})

    # 3 retry waits for 4 total attempts (0.1s, 0.5s, 2.0s)
    assert len(sleep_calls) == 3
    assert sleep_calls[0] < sleep_calls[1] < sleep_calls[2]


# ── budget cap ────────────────────────────────────────────────────────────────


def test_retry_budget_prevents_extra_attempts():
    """If elapsed time > budget after first retry, no further attempts occur."""
    connector = _connector()
    call_count = [0]

    def slow_fail(path, body):
        call_count[0] += 1
        raise _http_error(503)

    # Simulate 6 seconds elapsed after the first retry (budget is 5s)
    monotonic_values = [0.0, 0.1, 6.1, 6.2, 12.0, 12.1]
    idx = [0]

    def fake_monotonic():
        val = monotonic_values[min(idx[0], len(monotonic_values) - 1)]
        idx[0] += 1
        return val

    with patch.object(connector, "_post", side_effect=slow_fail):
        with patch("time.sleep"):
            with patch("time.monotonic", side_effect=fake_monotonic):
                connector.score_finding({"severity": "high"})

    # Should have stopped after budget exceeded; at most 2 network calls
    assert call_count[0] <= 2


# ── other methods also retry ──────────────────────────────────────────────────


def test_decide_go_no_go_retries_on_503():
    connector = _connector()
    attempts = [0]

    def flaky(path, body):
        attempts[0] += 1
        if attempts[0] == 1:
            raise _http_error(503)
        return {"decision": "allow", "blockers": []}

    with patch.object(connector, "_post", side_effect=flaky):
        with patch("time.sleep"):
            result = connector.decide_go_no_go("svc-1", [])

    assert result.source == "argus"
    assert attempts[0] == 2


def test_fetch_premium_rule_pack_retries_on_network_error():
    connector = _connector()
    attempts = [0]

    def flaky(path, params):
        attempts[0] += 1
        if attempts[0] == 1:
            raise _ArgusNetworkError("DNS failure")
        return {"rules": []}

    with patch.object(connector, "_get", side_effect=flaky):
        with patch("time.sleep"):
            result = connector.fetch_premium_rule_pack()

    assert result == {"rules": []}
    assert attempts[0] == 2
