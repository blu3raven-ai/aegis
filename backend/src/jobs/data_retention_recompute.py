"""Nightly data-retention evaluator job."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def trigger_data_retention_recompute(asset_ids: list[str]) -> None:
    """Evaluate data-retention rules across the given asset_ids."""
    from src.rules.data_retention_evaluator import evaluate_data_retention

    if not asset_ids:
        return

    try:
        result = evaluate_data_retention(asset_ids=asset_ids)
        logger.info(
            "Data retention evaluator: rules=%d scans=%d archived=%d deleted=%d",
            result.rules_evaluated,
            result.scans_checked,
            result.archived,
            result.deleted,
        )
    except Exception:
        logger.exception("Data retention recompute failed")
