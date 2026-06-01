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
    """Recompute SLA breach status for each org.

    Called by the scheduler at most once per hour. Errors per-org are
    logged and swallowed so one bad org doesn't block the rest.
    """
    from src.sla.service import get_sla_service

    service = get_sla_service()
    for org_id in org_ids:
        try:
            count = service.recompute_org(org_id)
            logger.info("SLA recompute: %d findings updated for org %s", count, org_id)
        except Exception:
            logger.exception("SLA recompute failed for org %s", org_id)
