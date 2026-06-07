"""Daily scanner-coverage recompute job for Rules P3.

How to wire into the existing AutoRerunScheduler:

  In backend/src/scheduler.py, add a call to
  trigger_scanner_coverage_recompute() inside the AutoRerunScheduler._tick()
  method. A daily schedule is appropriate — the existing convention is to
  use _matches_cron("0 4 * * *", now) (e.g. 04:00 UTC daily, off-hours):

      if _matches_cron("0 4 * * *", now):
          self._trigger_scanner_coverage_recompute(all_orgs)

  Then add the method:

      def _trigger_scanner_coverage_recompute(self, all_orgs: list[str]) -> None:
          from src.jobs.scanner_coverage_recompute import trigger_scanner_coverage_recompute
          trigger_scanner_coverage_recompute(all_orgs)

  This file intentionally avoids modifying scheduler.py directly to keep
  the commit blast radius small. Wire it in when scheduler.py is next
  touched (alongside the still-unwired SLA recompute).
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def trigger_scanner_coverage_recompute(org_ids: list[str]) -> None:
    """Recompute scanner-coverage rule violations for each org.

    Called by the scheduler at most once per day. Errors per-org are
    logged and swallowed so one bad org doesn't block the rest. Stale
    alerts are dispatched only when a fresh violation opens, so daily
    runs are safe from duplicate notifications.
    """
    from src.rules.scanner_coverage_evaluator import evaluate_scanner_coverage_for_org

    for org_id in org_ids:
        try:
            result = evaluate_scanner_coverage_for_org(org_id)
            logger.info(
                "Scanner coverage evaluator (org=%s): rules=%d repos=%d opened=%d resolved=%d stale_alerts=%d",
                org_id,
                result.rules_evaluated,
                result.repos_checked,
                result.violations_opened,
                result.violations_resolved,
                result.stale_alerts_dispatched,
            )
        except Exception:
            logger.exception("Scanner coverage recompute failed for org %s", org_id)
