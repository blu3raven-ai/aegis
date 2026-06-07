"""Nightly data-retention evaluator job for Rules P5.

How to wire into the existing AutoRerunScheduler:

  In backend/src/scheduler.py, add a call to
  trigger_data_retention_recompute() inside the AutoRerunScheduler._tick()
  method. The data-retention sweep can be heavy (delete actions cascade
  through findings/decisions) so an off-peak nightly schedule is preferred.
  The existing convention is _matches_cron("0 4 * * *", now) (04:00 UTC daily):

      if _matches_cron("0 4 * * *", now):
          self._trigger_data_retention_recompute(all_orgs)

  Then add the method:

      def _trigger_data_retention_recompute(self, all_orgs: list[str]) -> None:
          from src.jobs.data_retention_recompute import trigger_data_retention_recompute
          trigger_data_retention_recompute(all_orgs)

  This file intentionally avoids modifying scheduler.py directly to keep
  the commit blast radius small. Wire it in when scheduler.py is next
  touched (alongside the still-unwired SLA and scanner-coverage recomputes).
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def trigger_data_retention_recompute(org_ids: list[str]) -> None:
    """Evaluate data-retention rules per org. Archive/delete actions land in DB.

    Called by the scheduler at most once per day. Errors per-org are
    logged and swallowed so one bad org doesn't block the rest. The
    evaluator's idempotency (skipping already-archived rows; matching
    one rule per scan) keeps repeated runs safe.
    """
    from src.rules.data_retention_evaluator import evaluate_data_retention_for_org

    for org_id in org_ids:
        try:
            result = evaluate_data_retention_for_org(org_id)
            logger.info(
                "Data retention evaluator (org=%s): rules=%d scans=%d archived=%d deleted=%d",
                org_id,
                result.rules_evaluated,
                result.scans_checked,
                result.archived,
                result.deleted,
            )
        except Exception:
            logger.exception("Data retention recompute failed for org %s", org_id)
