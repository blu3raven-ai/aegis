"""Tests for CorrelationEngine with a real ArgusConnector injected.

Verifies that:
- Engine accepts an ArgusConnector via constructor injection
- RuleContext receives the injected connector
- Rules can call ctx.argus.score_finding() via the injected connector
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from testcontainers.redis import RedisContainer

from src.argus.connector import ArgusConnector, NullArgusConnector, RiskScore
from src.correlation.engine import CorrelationEngine
from src.correlation.rule import Rule, RuleContext


# ── helpers ───────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def redis_container():
    with RedisContainer("redis:7-alpine") as rc:
        yield rc


def _make_stream_cfg(rc) -> dict:
    host = rc.get_container_host_ip()
    port = rc.get_exposed_port(6379)
    return {"url": f"redis://{host}:{port}", "stream_prefix": "test.argus.", "max_len": 100}


def _redis_cfg(rc) -> dict:
    host = rc.get_container_host_ip()
    port = rc.get_exposed_port(6379)
    return {"url": f"redis://{host}:{port}"}


def _raw_event(event_type: str = "intel.cve_published", **payload) -> dict:
    return {
        "_stream_id": "1-0",
        "event_id": "EVT-ARGUS-001",
        "event_type": event_type,
        "org_id": "acme-org",
        "source_component": "test",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": payload,
    }


# ── capturing rule ────────────────────────────────────────────────────────────


class ArgusCapturingRule:
    """Rule that captures the argus connector it receives."""

    triggers: list[str] = ["intel.cve_published"]
    name: str = "argus_capturing_rule"

    def __init__(self):
        self.received_connector = None
        self.score_results: list[RiskScore] = []

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        self.received_connector = ctx.argus
        result = ctx.argus.score_finding({"severity": "high", "epss_score": 0.5})
        self.score_results.append(result)


# ── injection tests ───────────────────────────────────────────────────────────


def test_engine_injects_provided_connector(redis_container):
    """Engine forwards the explicitly supplied connector to RuleContext."""
    stream_cfg = _make_stream_cfg(redis_container)
    redis_cfg = _redis_cfg(redis_container)

    mock_connector = NullArgusConnector()
    engine = CorrelationEngine(stream_cfg, redis_cfg, argus=mock_connector)

    rule = ArgusCapturingRule()
    engine.register_rule(rule)
    engine.dispatch_event(_raw_event())

    assert rule.received_connector is mock_connector


def test_engine_defaults_to_null_connector_when_no_argus_env(redis_container, monkeypatch):
    """Engine creates NullArgusConnector when ARGUS_ENDPOINT is absent."""
    monkeypatch.delenv("ARGUS_ENDPOINT", raising=False)
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)

    stream_cfg = _make_stream_cfg(redis_container)
    redis_cfg = _redis_cfg(redis_container)

    engine = CorrelationEngine(stream_cfg, redis_cfg)  # no argus kwarg

    rule = ArgusCapturingRule()
    engine.register_rule(rule)
    engine.dispatch_event(_raw_event())

    assert isinstance(rule.received_connector, NullArgusConnector)


def test_engine_defaults_to_real_connector_when_env_set(redis_container, monkeypatch):
    """Engine creates real ArgusConnector when env vars are present."""
    monkeypatch.setenv("ARGUS_ENDPOINT", "https://argus.example.com")
    monkeypatch.setenv("ARGUS_API_KEY", "test-key")

    stream_cfg = _make_stream_cfg(redis_container)
    redis_cfg = _redis_cfg(redis_container)

    engine = CorrelationEngine(stream_cfg, redis_cfg)
    rule = ArgusCapturingRule()
    engine.register_rule(rule)
    engine.dispatch_event(_raw_event())

    assert isinstance(rule.received_connector, ArgusConnector)
    assert not isinstance(rule.received_connector, NullArgusConnector)


def test_rule_can_call_score_finding_via_ctx(redis_container):
    """Rule receives a callable argus connector — score_finding works end-to-end."""
    stream_cfg = _make_stream_cfg(redis_container)
    redis_cfg = _redis_cfg(redis_container)

    engine = CorrelationEngine(stream_cfg, redis_cfg, argus=NullArgusConnector())
    rule = ArgusCapturingRule()
    engine.register_rule(rule)
    engine.dispatch_event(_raw_event())

    assert len(rule.score_results) == 1
    result = rule.score_results[0]
    assert isinstance(result, RiskScore)
    assert result.source == "heuristic"
    assert 0 <= result.score <= 100


def test_engine_passes_same_connector_to_all_rules(redis_container):
    """All rules within a single dispatch share the same connector instance."""
    stream_cfg = _make_stream_cfg(redis_container)
    redis_cfg = _redis_cfg(redis_container)

    connector = NullArgusConnector()
    engine = CorrelationEngine(stream_cfg, redis_cfg, argus=connector)

    rule_a = ArgusCapturingRule()
    rule_a.name = "rule_a"

    rule_b = ArgusCapturingRule()
    rule_b.name = "rule_b"

    engine.register_rule(rule_a)
    engine.register_rule(rule_b)
    engine.dispatch_event(_raw_event())

    assert rule_a.received_connector is connector
    assert rule_b.received_connector is connector
