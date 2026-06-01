"""Rule 12 (Type 4): MTTR tracking — mean time to remediate per scanner/severity.

Fires on finding.closed (status=fixed). Computes the duration from
first_seen_at to now() and records the millisecond value into
temporal_aggregates with metric_type='mttr'. Averaging across the
time window is done at query time.

The payload shape from FindingClosedEvent is:
  { finding_id: int, reason: str, provenance_rule: str }

We need first_seen_at from the DB. To avoid an extra DB hop for every event
the rule accepts it as an optional payload field (`first_seen_at_utc`) written
by the scanner close path. When absent we fall back to querying the Finding.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select

from src.correlation.rule import Rule, RuleContext
from src.correlation.temporal import TemporalAggregator
from src.db.helpers import run_db
from src.db.models import Finding

logger = logging.getLogger(__name__)

_aggregator = TemporalAggregator()


class MttrTrackingRule:
    """Type 4 rule: records MTTR duration in ms on finding.closed."""

    triggers: list[str] = ["finding.closed"]
    name: str = "mttr_tracking"

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        payload = event.get("payload", {})
        org_id = event.get("org_id", "")
        finding_id = payload.get("finding_id")
        if not org_id or finding_id is None:
            return

        first_seen_at = _resolve_first_seen(payload, finding_id)
        if first_seen_at is None:
            logger.debug("mttr_tracking: first_seen_at unavailable for finding %s", finding_id)
            return

        now = datetime.now(timezone.utc)
        if first_seen_at.tzinfo is None:
            first_seen_at = first_seen_at.replace(tzinfo=timezone.utc)

        duration_ms = (now - first_seen_at).total_seconds() * 1000.0
        if duration_ms < 0:
            # Clock skew guard — discard obviously bad values.
            logger.warning("mttr_tracking: negative duration for finding %s, skipping", finding_id)
            return

        scanner_type = payload.get("scanner_type", "unknown")
        severity = payload.get("severity", "unknown")

        _aggregator.record(
            org_id=org_id,
            metric_type="mttr",
            dimension={"scanner_type": scanner_type, "severity": severity},
            value=duration_ms,
        )
        logger.debug(
            "mttr_tracking: recorded org=%s scanner=%s severity=%s duration_ms=%.0f",
            org_id, scanner_type, severity, duration_ms,
        )


def _resolve_first_seen(payload: dict, finding_id: int | str) -> datetime | None:
    """Return first_seen_at: from payload shortcut, then DB lookup."""
    raw = payload.get("first_seen_at_utc")
    if raw:
        try:
            return datetime.fromisoformat(str(raw))
        except ValueError:
            pass

    async def _fetch(session) -> datetime | None:
        result = await session.execute(
            select(Finding.first_seen_at).where(Finding.id == int(finding_id))
        )
        return result.scalar_one_or_none()

    return run_db(_fetch)
