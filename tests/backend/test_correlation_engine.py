"""Tests for CorrelationEngine — dispatch, circuit breaker, idempotency."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from testcontainers.redis import RedisContainer

from src.correlation.engine import CorrelationEngine, _CIRCUIT_BREAKER_THRESHOLD
from src.correlation.rule import Rule, RuleContext
from src.correlation.chain_graph_store import ChainGraphStore
from src.correlation.emit_interface import EmitInterface
from src.correlation.state import CorrelationState


# ── helpers ───────────────────────────────────────────────────────────────────


def _make_stream_cfg(redis_container) -> dict:
    host = redis_container.get_container_host_ip()
    port = redis_container.get_exposed_port(6379)
    return {
        "url": f"redis://{host}:{port}",
        "stream_prefix": "test.corr.",
        "max_len": 100,
    }


def _redis_cfg(redis_container) -> dict:
    host = redis_container.get_container_host_ip()
    port = redis_container.get_exposed_port(6379)
    return {"url": f"redis://{host}:{port}"}


def _raw_event(event_type: str = "code.push", **payload) -> dict:
    return {
        "_stream_id": "1-0",
        "event_id": "EVT001",
        "event_type": event_type,
        "org_id": "acme-org",
        "source_component": "test",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": payload,
    }


class CountingRule:
    """Rule that counts calls and records received event types."""

    triggers: list[str] = ["code.push", "intel.cve_published"]
    name: str = "counting_rule"

    def __init__(self):
        self.call_count = 0
        self.seen_types: list[str] = []

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        self.call_count += 1
        self.seen_types.append(event["event_type"])


class FailingRule:
    """Rule that always raises to test circuit breaker."""

    triggers: list[str] = ["code.push"]
    name: str = "failing_rule"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        raise RuntimeError("simulated rule failure")


class SometimesFailingRule:
    """Rule that fails N times then succeeds."""

    triggers: list[str] = ["code.push"]
    name: str = "sometimes_failing"

    def __init__(self, fail_count: int = 0):
        self._remaining = fail_count
        self.success_count = 0

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        if self._remaining > 0:
            self._remaining -= 1
            raise RuntimeError("planned failure")
        self.success_count += 1


@pytest.fixture(scope="module")
def redis_container():
    with RedisContainer("redis:7-alpine") as rc:
        yield rc


def _make_engine(redis_container) -> CorrelationEngine:
    return CorrelationEngine(
        stream_config=_make_stream_cfg(redis_container),
        redis_config=_redis_cfg(redis_container),
    )


# ── registration ──────────────────────────────────────────────────────────────


def test_register_rule_indexes_by_trigger(redis_container):
    engine = _make_engine(redis_container)
    rule = CountingRule()
    engine.register_rule(rule)
    assert "counting_rule" in engine._trigger_index["code.push"]
    assert "counting_rule" in engine._trigger_index["intel.cve_published"]


# ── dispatch_event ────────────────────────────────────────────────────────────


def test_dispatch_routes_to_matching_rules(redis_container):
    engine = _make_engine(redis_container)
    rule = CountingRule()
    engine.register_rule(rule)

    engine.dispatch_event(_raw_event("code.push"))
    assert rule.call_count == 1
    assert "code.push" in rule.seen_types


def test_dispatch_does_not_route_to_non_matching_rule(redis_container):
    engine = _make_engine(redis_container)
    rule = CountingRule()
    engine.register_rule(rule)

    engine.dispatch_event(_raw_event("scan.finding"))
    assert rule.call_count == 0


def test_dispatch_routes_multiple_rules(redis_container):
    engine = _make_engine(redis_container)
    rule1 = CountingRule()
    rule1.name = "counter_a"

    class AnotherCountingRule(CountingRule):
        name = "counter_b"

    rule2 = AnotherCountingRule()
    engine.register_rule(rule1)
    engine.register_rule(rule2)

    engine.dispatch_event(_raw_event("code.push"))
    assert rule1.call_count == 1
    assert rule2.call_count == 1


# ── circuit breaker ───────────────────────────────────────────────────────────


def test_circuit_breaker_trips_after_threshold_failures(redis_container, caplog):
    engine = _make_engine(redis_container)
    rule = FailingRule()
    engine.register_rule(rule)

    for _ in range(_CIRCUIT_BREAKER_THRESHOLD):
        engine.dispatch_event(_raw_event("code.push"))

    assert engine._breaker.is_open("failing_rule")


def test_circuit_breaker_open_rule_is_skipped(redis_container):
    engine = _make_engine(redis_container)
    rule = FailingRule()
    engine.register_rule(rule)
    tracking = []

    # Manually open the breaker
    engine._breaker._open.add("failing_rule")

    original_evaluate = rule.evaluate

    def counting_evaluate(event, ctx):
        tracking.append(event)
        return original_evaluate(event, ctx)

    rule.evaluate = counting_evaluate

    # Should not call evaluate at all when circuit is open
    engine.dispatch_event(_raw_event("code.push"))
    assert len(tracking) == 0


def test_circuit_breaker_resets_on_success(redis_container):
    engine = _make_engine(redis_container)
    # Fail twice (below threshold of 3), then succeed
    rule = SometimesFailingRule(fail_count=2)
    engine.register_rule(rule)

    engine.dispatch_event(_raw_event("code.push"))  # fail 1
    engine.dispatch_event(_raw_event("code.push"))  # fail 2
    engine.dispatch_event(_raw_event("code.push"))  # success → resets counter

    assert rule.success_count == 1
    # Counter reset means not tripped yet even though it failed before
    assert not engine._breaker.is_open("sometimes_failing")


def test_circuit_breaker_logs_critical_when_tripped(redis_container, caplog):
    import logging
    engine = _make_engine(redis_container)
    rule = FailingRule()
    rule.name = "critical_test_rule"
    engine.register_rule(rule)

    with caplog.at_level(logging.CRITICAL):
        for _ in range(_CIRCUIT_BREAKER_THRESHOLD):
            engine.dispatch_event(_raw_event("code.push"))

    assert any("DISABLED" in r.message for r in caplog.records)


# ── start / stop (integration with real Redis) ────────────────────────────────


def test_engine_starts_and_stops(redis_container):
    engine = _make_engine(redis_container)
    rule = CountingRule()
    engine.register_rule(rule)

    engine.start()
    assert engine.is_running

    engine.stop(timeout=3.0)
    assert not engine.is_running


def test_engine_start_is_idempotent(redis_container):
    engine = _make_engine(redis_container)
    engine.register_rule(CountingRule())
    engine.start()
    engine.start()  # second call should be no-op
    assert engine.is_running
    engine.stop(timeout=3.0)
