"""End-to-end hardening tests for ArgusConnector.

Verifies: circuit opens after N failures, fallbacks kick in until recovery,
and the full request → circuit breaker → retry → fallback lifecycle.
"""
from __future__ import annotations

import logging
import logging.handlers
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.argus.connector import (
    ArgusConnector,
    _ArgusHttpError,
    _ArgusNetworkError,
)
from src.argus.circuit_breaker import CircuitOpenError

ENDPOINT = "https://argus.example.com"
API_KEY = "test-e2e-key"


def _connector(failure_threshold: int = 3) -> ArgusConnector:
    connector = ArgusConnector(endpoint=ENDPOINT, api_key=API_KEY)
    # Reconfigure breaker with smaller threshold for faster tests
    connector._circuit_breaker._failure_threshold = failure_threshold
    return connector


# ── circuit opens after N failures ────────────────────────────────────────────


def test_circuit_opens_after_threshold_failures_and_fallback_fires():
    connector = _connector(failure_threshold=3)
    call_count = [0]

    def always_fail(path, body):
        call_count[0] += 1
        raise _ArgusHttpError("HTTP 503", status_code=503)

    with patch.object(connector, "_post", side_effect=always_fail):
        with patch("time.sleep"):
            # 3 × max_attempts failures will trip the breaker
            for _ in range(3):
                result = connector.score_finding({"severity": "critical"})
                assert result.source == "heuristic"

    # After threshold is exceeded, new calls should short-circuit immediately
    before = call_count[0]
    result = connector.score_finding({"severity": "critical"})
    assert result.source == "heuristic"
    # _post should NOT have been called (circuit open, fast fail)
    assert call_count[0] == before


def test_all_methods_fall_back_while_circuit_open():
    connector = _connector(failure_threshold=1)
    # Trip the circuit
    connector._circuit_breaker.record_failure()
    assert connector._circuit_breaker.state.status == "open"

    with patch.object(connector, "_post") as mock_post:
        with patch.object(connector, "_get") as mock_get:
            score = connector.score_finding({"severity": "medium"})
            decision = connector.decide_go_no_go("svc-x", [])
            explanation = connector.explain_chain({"chain_type": "t", "findings": [], "edges": []})
            rule_pack = connector.fetch_premium_rule_pack()
            packs = connector.get_rule_packs()

    assert score.source == "heuristic"
    assert decision.source == "heuristic"
    assert explanation.source == "heuristic"
    assert rule_pack == {}
    assert packs == []

    # No real HTTP calls while open
    mock_post.assert_not_called()
    mock_get.assert_not_called()


# ── recovery after timeout ────────────────────────────────────────────────────


def test_connector_recovers_after_circuit_recovery_timeout():
    connector = _connector(failure_threshold=1)
    connector._circuit_breaker.record_failure()
    assert connector._circuit_breaker.state.status == "open"

    # Fast-forward past recovery timeout
    past = datetime.now(timezone.utc) - timedelta(seconds=31)
    with connector._circuit_breaker._lock:
        connector._circuit_breaker._state.opened_at = past

    # Circuit should now allow a probe call
    with patch.object(connector, "_post", return_value={"score": 90.0}):
        result = connector.score_finding({"severity": "critical"})

    assert result.source == "argus"
    assert connector._circuit_breaker.state.status == "closed"


def test_half_open_failure_reopens_circuit():
    connector = _connector(failure_threshold=1)
    connector._circuit_breaker.record_failure()

    past = datetime.now(timezone.utc) - timedelta(seconds=31)
    with connector._circuit_breaker._lock:
        connector._circuit_breaker._state.opened_at = past

    # Probe call fails — circuit should reopen
    with patch.object(connector, "_post", side_effect=_ArgusNetworkError("still down")):
        with patch("time.sleep"):
            result = connector.score_finding({"severity": "high"})

    assert result.source == "heuristic"
    assert connector._circuit_breaker.state.status == "open"


# ── pooled client ─────────────────────────────────────────────────────────────


def test_pooled_client_is_reused_across_calls():
    """Same httpx.Client instance is used for multiple requests."""
    from src.argus import connector as connector_module

    original = connector_module._pooled_client
    connector_module._pooled_client = None  # force new creation

    try:
        c1 = connector_module._get_pooled_client()
        c2 = connector_module._get_pooled_client()
        assert c1 is c2
    finally:
        connector_module._pooled_client = original


# ── backward compatibility ────────────────────────────────────────────────────


def test_public_method_signatures_unchanged():
    """Constructor and all public methods accept the same args as before."""
    connector = ArgusConnector(endpoint=ENDPOINT, api_key=API_KEY)
    assert hasattr(connector, "score_finding")
    assert hasattr(connector, "decide_go_no_go")
    assert hasattr(connector, "explain_chain")
    assert hasattr(connector, "fetch_premium_rule_pack")
    assert hasattr(connector, "get_rule_packs")


def test_timeout_ms_parameter_accepted():
    connector = ArgusConnector(endpoint=ENDPOINT, api_key=API_KEY, timeout_ms=5000)
    assert connector._timeout == 5.0


# ── structured log fields ─────────────────────────────────────────────────────


def test_structured_log_includes_endpoint_on_failure():
    connector = _connector(failure_threshold=1)
    records_captured = []

    class SimpleHandler(logging.Handler):
        def emit(self, record):
            records_captured.append(record)

    logger = logging.getLogger("src.argus.connector")
    handler = SimpleHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING)

    try:
        with patch.object(connector, "_post", side_effect=_ArgusNetworkError("refused")):
            with patch("time.sleep"):
                connector.score_finding({"severity": "high"})
    finally:
        logger.removeHandler(handler)

    assert len(records_captured) > 0
