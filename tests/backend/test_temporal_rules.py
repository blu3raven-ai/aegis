"""Tests for Phase 11 Type 4 temporal correlation rules.

Uses real testcontainers Postgres (session-level fixture from conftest).
Each temporal rule is tested for:
  - correct trigger event_type
  - correct dimension recorded in temporal_aggregates
  - edge-case / missing field handling
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.argus.connector import NullArgusConnector
from src.correlation.rule import RuleContext
from src.correlation.rules.temporal.attribution_rollup import AttributionRollupRule
from src.correlation.rules.temporal.severity_velocity import SeverityVelocityRule
from src.correlation.rules.temporal.mttr_tracking import MttrTrackingRule
from src.correlation.rules.temporal.anomaly_detection import AnomalyDetectionRule
from src.correlation.temporal import TemporalAggregator
from src.correlation.state import CorrelationState
from src.db.helpers import run_db
from src.db.models import Finding, TemporalAggregate
from sqlalchemy import delete, insert

ORG = "acme-org"


# ── shared helpers ────────────────────────────────────────────────────────────


def _ctx() -> RuleContext:
    return RuleContext(
        state=CorrelationState(),
        argus=NullArgusConnector(),
        emit=MagicMock(),
    )


def _event(event_type: str, org: str = ORG, **payload) -> dict:
    return {
        "event_id": "evt-test-001",
        "event_type": event_type,
        "org_id": org,
        "source_component": "test",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(delete(TemporalAggregate).where(TemporalAggregate.org_id == ORG))
        await session.execute(delete(Finding).where(Finding.org == ORG))
    run_db(_del)
    yield


# ── AttributionRollupRule ──────────────────────────────────────────────────────


class TestAttributionRollupRule:
    def test_trigger(self):
        assert "finding.created" in AttributionRollupRule.triggers

    def test_records_dimension(self):
        rule = AttributionRollupRule()
        rule.evaluate(
            _event("finding.created",
                   scanner_type="deps",
                   severity="critical",
                   introduced_by_author="dev@example.org"),
            _ctx(),
        )

        agg = TemporalAggregator()
        points = agg.query(org_id=ORG, metric_type="findings_introduced")
        assert len(points) == 1
        p = points[0]
        assert p.dimension["author"] == "dev@example.org"
        assert p.dimension["scanner_type"] == "deps"
        assert p.dimension["severity"] == "critical"
        assert p.value == 1.0

    def test_unknown_author_fallback(self):
        rule = AttributionRollupRule()
        rule.evaluate(_event("finding.created", scanner_type="sast", severity="high"), _ctx())

        agg = TemporalAggregator()
        points = agg.query(org_id=ORG, metric_type="findings_introduced")
        assert points[0].dimension["author"] == "unknown"

    def test_missing_org_id_skipped(self):
        rule = AttributionRollupRule()
        ev = _event("finding.created", scanner_type="deps", severity="low")
        ev["org_id"] = ""
        rule.evaluate(ev, _ctx())

        agg = TemporalAggregator()
        assert agg.query(org_id=ORG, metric_type="findings_introduced") == []

    def test_accumulates_multiple_events(self):
        rule = AttributionRollupRule()
        for _ in range(5):
            rule.evaluate(
                _event("finding.created",
                       scanner_type="secrets",
                       severity="critical",
                       introduced_by_author="eng@example.org"),
                _ctx(),
            )

        agg = TemporalAggregator()
        points = agg.query(
            org_id=ORG,
            metric_type="findings_introduced",
            dimension_filter={"author": "eng@example.org"},
        )
        assert points[0].value == 5.0


# ── SeverityVelocityRule ───────────────────────────────────────────────────────


class TestSeverityVelocityRule:
    def test_trigger(self):
        assert "finding.created" in SeverityVelocityRule.triggers

    def test_records_scanner_severity_dimension(self):
        rule = SeverityVelocityRule()
        rule.evaluate(
            _event("finding.created", scanner_type="container", severity="high"),
            _ctx(),
        )

        agg = TemporalAggregator()
        points = agg.query(org_id=ORG, metric_type="severity_velocity")
        assert len(points) == 1
        p = points[0]
        assert p.dimension["scanner_type"] == "container"
        assert p.dimension["severity"] == "high"
        # Should not store author dimension
        assert "author" not in p.dimension

    def test_missing_org_id_skipped(self):
        rule = SeverityVelocityRule()
        ev = _event("finding.created", scanner_type="sast", severity="medium")
        ev["org_id"] = ""
        rule.evaluate(ev, _ctx())

        agg = TemporalAggregator()
        assert agg.query(org_id=ORG, metric_type="severity_velocity") == []


# ── MttrTrackingRule ──────────────────────────────────────────────────────────


class TestMttrTrackingRule:
    def test_trigger(self):
        assert "finding.closed" in MttrTrackingRule.triggers

    def test_records_mttr_from_payload_shortcut(self):
        rule = MttrTrackingRule()
        first_seen = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        rule.evaluate(
            _event("finding.closed",
                   finding_id=999,
                   scanner_type="secrets",
                   severity="critical",
                   first_seen_at_utc=first_seen),
            _ctx(),
        )

        agg = TemporalAggregator()
        points = agg.query(org_id=ORG, metric_type="mttr")
        assert len(points) == 1
        p = points[0]
        assert p.dimension["scanner_type"] == "secrets"
        assert p.dimension["severity"] == "critical"
        # 3 days in ms ≈ 259_200_000; allow generous tolerance
        assert p.value > 250_000_000

    def test_records_mttr_from_db_lookup(self):
        """Falls back to DB when first_seen_at_utc is absent in payload."""
        first_seen = datetime.now(timezone.utc) - timedelta(days=1)

        async def _insert(session):
            f = Finding(
                id=None,
                tool="deps",
                org=ORG,
                repo=f"{ORG}/myrepo",
                identity_key="mttr-test-key",
                state="open",
                severity="high",
                detail={},
                first_seen_at=first_seen,
            )
            session.add(f)
            await session.flush()
            return f.id

        fid = run_db(_insert)

        rule = MttrTrackingRule()
        rule.evaluate(
            _event("finding.closed",
                   finding_id=fid,
                   scanner_type="deps",
                   severity="high"),
            _ctx(),
        )

        agg = TemporalAggregator()
        points = agg.query(org_id=ORG, metric_type="mttr")
        assert len(points) == 1
        assert points[0].value > 80_000_000  # at least ~1 day in ms

    def test_missing_finding_id_skipped(self):
        rule = MttrTrackingRule()
        rule.evaluate(_event("finding.closed", scanner_type="sast"), _ctx())

        agg = TemporalAggregator()
        assert agg.query(org_id=ORG, metric_type="mttr") == []

    def test_missing_org_id_skipped(self):
        rule = MttrTrackingRule()
        ev = _event("finding.closed", finding_id=1)
        ev["org_id"] = ""
        rule.evaluate(ev, _ctx())

        agg = TemporalAggregator()
        assert agg.query(org_id=ORG, metric_type="mttr") == []


# ── AnomalyDetectionRule ───────────────────────────────────────────────────────


class TestAnomalyDetectionRule:
    def test_trigger(self):
        assert "finding.created" in AnomalyDetectionRule.triggers

    def test_no_anomaly_when_no_baseline(self):
        """With no prior history the rule silently skips the spike check."""
        rule = AnomalyDetectionRule()
        with patch(
            "src.correlation.rules.temporal.anomaly_detection._emit_anomaly"
        ) as mock_emit:
            rule.evaluate(
                _event("finding.created", scanner_type="deps", severity="critical"),
                _ctx(),
            )
            mock_emit.assert_not_called()

    def test_no_anomaly_below_threshold(self):
        """A normal rate should not trigger an anomaly."""
        agg = TemporalAggregator()
        now = datetime.now(timezone.utc)
        dim = {"scanner_type": "secrets", "severity": "high"}

        # Seed 7 days of daily baseline: 240 findings/day → hourly avg = 10/hr.
        # Adding 1 finding in the current hour gives multiplier = 1/10 = 0.1 < 3×.
        for day_offset in range(1, 8):
            ts = now - timedelta(days=day_offset)
            agg.record(org_id=ORG, metric_type="severity_velocity", dimension=dim,
                       bucket_size="1d", timestamp=ts, value=240.0)

        rule = AnomalyDetectionRule()
        with patch(
            "src.correlation.rules.temporal.anomaly_detection._emit_anomaly"
        ) as mock_emit:
            # One finding in this hour — well below the 3× threshold (1 vs 10/hr avg)
            rule.evaluate(
                _event("finding.created", scanner_type="secrets", severity="high"),
                _ctx(),
            )
            mock_emit.assert_not_called()

    def test_anomaly_emitted_on_spike(self):
        """A >3× hourly spike should emit AnomalyDetectedEvent."""
        agg = TemporalAggregator()
        now = datetime.now(timezone.utc)
        dim = {"scanner_type": "sast", "severity": "critical"}

        # Seed 7 days of daily baseline: 2 findings/day → hourly avg ≈ 0.083
        for day_offset in range(1, 8):
            ts = now - timedelta(days=day_offset)
            agg.record(org_id=ORG, metric_type="severity_velocity", dimension=dim,
                       bucket_size="1d", timestamp=ts, value=2.0)

        # Pre-seed the current hour bucket to make the window_count spike
        # before triggering the rule (simulating many findings already this hour).
        # We need window_count / (2/24) >= 3 → window_count >= 0.25 → 1 is enough
        # but let's make it unambiguous: 10 findings this hour vs avg 0.083/h
        agg.record(org_id=ORG, metric_type="severity_velocity", dimension=dim,
                   bucket_size="1h", timestamp=now, value=9.0)

        rule = AnomalyDetectionRule()
        with patch(
            "src.correlation.rules.temporal.anomaly_detection._emit_anomaly"
        ) as mock_emit:
            # +1 more finding (the rule also records to 1h inside evaluate)
            rule.evaluate(
                _event("finding.created", scanner_type="sast", severity="critical"),
                _ctx(),
            )
            mock_emit.assert_called_once()
            kwargs = mock_emit.call_args.kwargs
            assert kwargs["org_id"] == ORG
            assert kwargs["scanner_type"] == "sast"
            assert kwargs["severity"] == "critical"
            assert kwargs["multiplier"] >= 3.0
