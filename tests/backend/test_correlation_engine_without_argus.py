"""Tests for CorrelationEngine without Argus configured (Mode A).

Verifies that:
- Engine works end-to-end when ARGUS_ENDPOINT / ARGUS_API_KEY are absent
- Rules receive NullArgusConnector and produce heuristic results
- No network calls are attempted
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from testcontainers.redis import RedisContainer

from src.argus.connector import NullArgusConnector, RiskScore
from src.correlation.engine import CorrelationEngine
from src.correlation.rule import RuleContext
from src.correlation.rules.intel_match import IntelMatchRule
from src.correlation.rules.epss_escalation import EpssEscalationRule


# ── helpers ───────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def redis_container():
    with RedisContainer("redis:7-alpine") as rc:
        yield rc


def _stream_cfg(rc) -> dict:
    host = rc.get_container_host_ip()
    port = rc.get_exposed_port(6379)
    return {"url": f"redis://{host}:{port}", "stream_prefix": "test.noargus.", "max_len": 100}


def _redis_cfg(rc) -> dict:
    host = rc.get_container_host_ip()
    port = rc.get_exposed_port(6379)
    return {"url": f"redis://{host}:{port}"}


# ── rules work without argus ──────────────────────────────────────────────────


class ScoreCollectorRule:
    """Rule that calls ctx.argus.score_finding and stores the result."""

    triggers: list[str] = ["intel.cve_published"]
    name: str = "score_collector"

    def __init__(self):
        self.scores: list[RiskScore] = []
        self.connector_type: str = ""

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        self.connector_type = type(ctx.argus).__name__
        score = ctx.argus.score_finding({"severity": "high", "epss_score": 0.6})
        self.scores.append(score)


def _intel_event(**payload) -> dict:
    return {
        "_stream_id": "1-0",
        "event_id": "noargus-evt-001",
        "event_type": "intel.cve_published",
        "org_id": "acme-org",
        "source_component": "test",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": {"cve_id": "CVE-2024-0001", "affected_package": "lodash",
                    "affected_version": "4.17.21", "severity": "high",
                    "epss_score": 0.6, **payload},
    }


def test_engine_uses_null_connector_when_env_unset(redis_container, monkeypatch):
    monkeypatch.delenv("ARGUS_ENDPOINT", raising=False)
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)

    engine = CorrelationEngine(_stream_cfg(redis_container), _redis_cfg(redis_container))
    rule = ScoreCollectorRule()
    engine.register_rule(rule)
    engine.dispatch_event(_intel_event())

    assert rule.connector_type == "NullArgusConnector"


def test_null_connector_produces_heuristic_scores(redis_container, monkeypatch):
    monkeypatch.delenv("ARGUS_ENDPOINT", raising=False)
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)

    engine = CorrelationEngine(_stream_cfg(redis_container), _redis_cfg(redis_container))
    rule = ScoreCollectorRule()
    engine.register_rule(rule)
    engine.dispatch_event(_intel_event())

    assert len(rule.scores) == 1
    assert rule.scores[0].source == "heuristic"
    assert 0 <= rule.scores[0].score <= 100


def test_no_network_calls_when_argus_unconfigured(redis_container, monkeypatch):
    monkeypatch.delenv("ARGUS_ENDPOINT", raising=False)
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)

    with patch("httpx.Client") as mock_http:
        engine = CorrelationEngine(_stream_cfg(redis_container), _redis_cfg(redis_container))
        rule = ScoreCollectorRule()
        engine.register_rule(rule)
        engine.dispatch_event(_intel_event())

    mock_http.assert_not_called()


def test_intel_match_rule_works_without_argus(redis_container, monkeypatch):
    """Rule 1 runs end-to-end in Mode A — emit_finding is called, no crash."""
    monkeypatch.delenv("ARGUS_ENDPOINT", raising=False)
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)

    engine = CorrelationEngine(_stream_cfg(redis_container), _redis_cfg(redis_container))

    rule = IntelMatchRule()
    engine.register_rule(rule)

    state = MagicMock()
    state.lookup_sboms_containing.return_value = [
        {"org": "acme-org", "repo": "acme-org/app", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}
    ]
    state.get_setting.return_value = None
    mock_emit = MagicMock()

    engine._state = state
    engine._emit = mock_emit

    engine.dispatch_event(_intel_event())

    mock_emit.emit_finding.assert_called_once()
    detail = mock_emit.emit_finding.call_args[0][0]["detail"]
    assert "risk_score" in detail
    assert "risk_source" in detail
    assert detail["risk_source"] == "heuristic"


def test_epss_escalation_rule_works_without_argus(redis_container, monkeypatch):
    """Rule 5 runs end-to-end in Mode A — emit_severity_change is called, no crash."""
    monkeypatch.delenv("ARGUS_ENDPOINT", raising=False)
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)

    engine = CorrelationEngine(_stream_cfg(redis_container), _redis_cfg(redis_container))

    rule = EpssEscalationRule()
    engine.register_rule(rule)

    state = MagicMock()
    state.lookup_findings.return_value = [
        {"id": 42, "severity": "medium", "state": "open", "detail": {"cve_id": "CVE-2024-0099"}}
    ]
    state.get_setting.return_value = 0.7
    mock_emit = MagicMock()

    engine._state = state
    engine._emit = mock_emit

    epss_event = {
        "_stream_id": "1-0",
        "event_id": "noargus-epss-001",
        "event_type": "intel.epss_changed",
        "org_id": "acme-org",
        "source_component": "test",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": {"cve_id": "CVE-2024-0099", "new_epss": 0.85, "old_epss": 0.2},
    }
    engine.dispatch_event(epss_event)

    mock_emit.emit_severity_change.assert_called_once()
