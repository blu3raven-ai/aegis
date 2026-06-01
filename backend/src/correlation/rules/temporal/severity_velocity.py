"""Rule 11 (Type 4): Severity velocity — findings-per-day trend per scanner/severity.

Fires on finding.created. Records a +1 keyed by (scanner_type, severity)
so the velocity chart can show whether a scanner's critical output is trending
up or down over time.
"""
from __future__ import annotations

import logging

from src.correlation.rule import Rule, RuleContext
from src.correlation.temporal import TemporalAggregator

logger = logging.getLogger(__name__)

_aggregator = TemporalAggregator()


class SeverityVelocityRule:
    """Type 4 rule: daily rate of new findings per scanner/severity pair."""

    triggers: list[str] = ["finding.created"]
    name: str = "severity_velocity"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        payload = event.get("payload", {})
        org_id = event.get("org_id", "")
        if not org_id:
            return

        scanner_type = payload.get("scanner_type", "unknown")
        severity = payload.get("severity", "unknown")

        _aggregator.record(
            org_id=org_id,
            metric_type="severity_velocity",
            dimension={"scanner_type": scanner_type, "severity": severity},
        )
        logger.debug(
            "severity_velocity: recorded org=%s scanner=%s severity=%s",
            org_id, scanner_type, severity,
        )
