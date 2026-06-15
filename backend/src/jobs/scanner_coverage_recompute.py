"""Daily scanner-coverage recompute job."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def trigger_scanner_coverage_recompute(asset_ids: list[str]) -> None:
    """Recompute scanner-coverage rule violations across the given asset_ids."""
    from src.rules.scanner_coverage_evaluator import evaluate_scanner_coverage

    if not asset_ids:
        return

    try:
        result = evaluate_scanner_coverage(asset_ids=asset_ids)
        logger.info(
            "Scanner coverage evaluator: rules=%d repos=%d opened=%d resolved=%d stale_alerts=%d",
            result.rules_evaluated,
            result.repos_checked,
            result.violations_opened,
            result.violations_resolved,
            result.stale_alerts_dispatched,
        )
    except Exception:
        logger.exception("Scanner coverage recompute failed")
