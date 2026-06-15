"""Hourly SLA breach recompute job."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def trigger_sla_recompute(asset_ids: list[str]) -> None:
    """Recompute SLA rule violations and fire escalations across the given asset_ids."""
    from src.rules.sla_evaluator import (
        evaluate_sla_escalations,
        evaluate_sla_rules,
    )

    if not asset_ids:
        return

    try:
        result = evaluate_sla_rules(asset_ids=asset_ids)
        logger.info(
            "SLA evaluator: rules=%d findings=%d opened=%d resolved=%d",
            result.rules_evaluated,
            result.findings_checked,
            result.violations_opened,
            result.violations_resolved,
        )
        fired = evaluate_sla_escalations()
        if fired:
            logger.info("SLA escalations fired: %d", fired)
    except Exception:
        logger.exception("SLA recompute failed")
