"""Rule 13 (Type 4): Anomaly detection — spike in finding rate per time window.

Fires on finding.created. Computes the count of findings in a short sliding
window (1h bucket) and compares it to the trailing-7-day daily average for
the same (org, scanner_type, severity) dimension. When the hourly rate
exceeds 3× the trailing average it emits intel.anomaly_detected for alerting.

The trailing average uses severity_velocity daily buckets that are already
written by SeverityVelocityRule — no extra DB reads beyond what we already
store.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from src.correlation.rule import Rule, RuleContext
from src.correlation.temporal import TemporalAggregator, _floor_bucket
from src.shared.event_types.intel import AnomalyDetectedEvent
from src.shared.event_publisher import get_event_publisher

logger = logging.getLogger(__name__)

# A spike is defined as the current-hour count exceeding this multiple of the
# trailing daily average.
_SPIKE_MULTIPLIER = 3.0

# How many trailing days to use for the baseline calculation.
_BASELINE_DAYS = 7

_aggregator = TemporalAggregator()


class AnomalyDetectionRule:
    """Type 4 rule: emit intel.anomaly_detected when hourly rate spikes."""

    triggers: list[str] = ["finding.created"]
    name: str = "anomaly_detection"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        payload = event.get("payload", {})
        org_id = event.get("org_id", "")
        if not org_id:
            return

        scanner_type = payload.get("scanner_type", "unknown")
        severity = payload.get("severity", "unknown")

        # Record the current finding into the hourly bucket first so it is
        # included in the window check below.
        _aggregator.record(
            org_id=org_id,
            metric_type="severity_velocity",
            dimension={"scanner_type": scanner_type, "severity": severity},
            bucket_size="1h",
        )

        now = datetime.now(timezone.utc)
        current_hour_start = _floor_bucket(now, "1h")

        # Fetch the current hourly count.
        window_points = _aggregator.query(
            org_id=org_id,
            metric_type="severity_velocity",
            dimension_filter={"scanner_type": scanner_type, "severity": severity},
            bucket_size="1h",
            since=current_hour_start,
            until=now,
        )
        window_count = sum(p.value for p in window_points)

        # Fetch trailing-7-day daily buckets to establish baseline.
        baseline_since = now - timedelta(days=_BASELINE_DAYS)
        baseline_points = _aggregator.query(
            org_id=org_id,
            metric_type="severity_velocity",
            dimension_filter={"scanner_type": scanner_type, "severity": severity},
            bucket_size="1d",
            since=baseline_since,
            until=now,
        )

        if not baseline_points:
            # Not enough history to establish a baseline; skip anomaly check.
            return

        # Daily average over the window — converted to hourly for fair comparison.
        daily_total = sum(p.value for p in baseline_points)
        daily_avg = daily_total / len(baseline_points)
        hourly_baseline = daily_avg / 24.0

        if hourly_baseline <= 0:
            return

        multiplier = window_count / hourly_baseline
        if multiplier < _SPIKE_MULTIPLIER:
            return

        logger.warning(
            "anomaly_detection: spike detected org=%s scanner=%s severity=%s "
            "window=%d baseline_hourly=%.2f multiplier=%.1f",
            org_id, scanner_type, severity, window_count, hourly_baseline, multiplier,
        )

        _emit_anomaly(
            org_id=org_id,
            scanner_type=scanner_type,
            severity=severity,
            window_count=int(window_count),
            baseline=hourly_baseline,
            multiplier=multiplier,
        )


def _emit_anomaly(
    *,
    org_id: str,
    scanner_type: str,
    severity: str,
    window_count: int,
    baseline: float,
    multiplier: float,
) -> None:
    try:
        get_event_publisher().publish(
            AnomalyDetectedEvent(
                org_id=org_id,
                source_component="correlation_engine",
                payload={
                    "window_count": window_count,
                    "baseline": baseline,
                    "multiplier": multiplier,
                    "scanner_type": scanner_type,
                    "severity": severity,
                },
            )
        )
    except Exception:
        logger.exception("anomaly_detection: failed to emit AnomalyDetectedEvent")
