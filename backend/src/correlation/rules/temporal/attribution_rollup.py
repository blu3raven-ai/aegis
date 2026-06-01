"""Rule 10 (Type 4): Attribution rollup — per-author/scanner/severity trends.

Fires on every finding.created event. Records a +1 into temporal_aggregates
keyed by (author, scanner_type, severity) so the dashboard can show "which
author introduced the most critical findings this week."

Author comes from introduced_by_author on the finding payload; when absent
the bucket uses author=unknown so totals always add up.
"""
from __future__ import annotations

import logging

from src.correlation.rule import Rule, RuleContext
from src.correlation.temporal import TemporalAggregator

logger = logging.getLogger(__name__)

_aggregator = TemporalAggregator()


class AttributionRollupRule:
    """Type 4 rule: per-author finding attribution rolled up daily."""

    triggers: list[str] = ["finding.created"]
    name: str = "attribution_rollup"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        payload = event.get("payload", {})
        org_id = event.get("org_id", "")
        if not org_id:
            return

        scanner_type = payload.get("scanner_type", "unknown")
        severity = payload.get("severity", "unknown")
        author = payload.get("introduced_by_author") or "unknown"

        _aggregator.record(
            org_id=org_id,
            metric_type="findings_introduced",
            dimension={
                "author": author,
                "scanner_type": scanner_type,
                "severity": severity,
            },
        )
        logger.debug(
            "attribution_rollup: recorded org=%s author=%s scanner=%s severity=%s",
            org_id, author, scanner_type, severity,
        )
