"""Hourly SLA breach recompute job for Phase 47.

How to wire into the existing AutoRerunScheduler:

  In backend/src/scheduler.py, add a call to trigger_sla_recompute() inside
  the AutoRerunScheduler._tick() method. The cron expression "0 * * * *"
  (every hour on the hour) is the recommended schedule:

      if _matches_cron("0 * * * *", now):
          self._trigger_sla_recompute(all_orgs)

  Then add the method:

      def _trigger_sla_recompute(self, all_orgs: list[str]) -> None:
          from src.jobs.sla_recompute import trigger_sla_recompute
          trigger_sla_recompute(all_orgs)

  This file intentionally avoids modifying scheduler.py directly so that
  other in-flight phases (44, 46) don't see merge conflicts. Wire it in
  when the scheduler is next touched.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def trigger_sla_recompute(org_ids: list[str]) -> None:
    """Recompute SLA rule violations and fire escalations for each org.

    Called by the scheduler at most once per hour. Errors per-org are
    logged and swallowed so one bad org doesn't block the rest.

    The evaluator dual-writes the legacy ``FindingSlaStatus`` table, so the
    previous ``SlaService.recompute_org`` call is no longer needed here.
    """
    from src.rules.sla_evaluator import (
        evaluate_sla_escalations_for_org,
        evaluate_sla_rules_for_org,
    )

    for org_id in org_ids:
        try:
            result = evaluate_sla_rules_for_org(org_id)
            logger.info(
                "SLA evaluator (org=%s): rules=%d findings=%d opened=%d resolved=%d",
                org_id,
                result.rules_evaluated,
                result.findings_checked,
                result.violations_opened,
                result.violations_resolved,
            )
            fired = evaluate_sla_escalations_for_org(org_id)
            if fired:
                logger.info("SLA escalations fired (org=%s): %d", org_id, fired)
        except Exception:
            logger.exception("SLA recompute failed for org %s", org_id)
