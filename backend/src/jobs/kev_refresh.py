"""CISA KEV catalog refresh job.

This module exposes a single callable, refresh_kev_catalog(), which fetches
the current CISA KEV feed and upserts it into the database.

Wiring options (choose one per deployment):

  1. AutoRerunScheduler (preferred for monolith):
       Add a _trigger_kev_refresh() method to AutoRerunScheduler in
       src/scheduler.py and call it from _tick() at a daily schedule, e.g.
       cron "0 3 * * *" (03:00 UTC).

  2. External cron / sidecar:
       Call `python -m src.jobs.kev_refresh` directly, or invoke
       refresh_kev_catalog() from an admin CLI entrypoint.  This module
       is importable with no side effects — the refresh only runs when
       refresh_kev_catalog() is explicitly called.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def refresh_kev_catalog() -> dict:
    """Fetch the CISA KEV catalog and upsert into the database.

    Designed to be called from a scheduler tick or an admin CLI command.
    Returns a summary dict so callers can log or surface the result.

    Fetch failures are re-raised so the scheduler can decide whether to
    retry — we do not silently swallow transport errors here.
    """
    from src.kev.fetcher import fetch_kev_catalog
    from src.kev.service import KevService

    logger.info("kev_refresh: starting catalog fetch")
    entries = fetch_kev_catalog()
    logger.info("kev_refresh: fetched %d entries, upserting", len(entries))

    service = KevService()
    new_cve_ids = service.upsert_catalog(entries)

    # KEV state changes bump risk_score for every finding whose CVE was
    # added or removed — recompute across orgs so the UI reflects the feed.
    from src.db.helpers import run_db
    from src.findings.risk_score import recompute_finding_risk_scores

    async def _rescore(session):
        return await recompute_finding_risk_scores(session)

    rescored = run_db(_rescore)

    # Notify users whose repositories are affected by the newly KEV-listed CVEs.
    notified = 0
    if new_cve_ids:
        from src.notifications.producers import notify_kev_affected_users

        async def _notify(session):
            return await notify_kev_affected_users(session, new_cve_ids)

        notified = run_db(_notify)

    logger.info(
        "kev_refresh: done — %d new entries added, %d findings rescored, %d users notified",
        len(new_cve_ids), rescored, notified,
    )
    return {
        "fetched": len(entries),
        "new": len(new_cve_ids),
        "rescored": rescored,
        "notified": notified,
    }


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    result = refresh_kev_catalog()
    print(f"KEV refresh complete: {result['fetched']} entries fetched, {result['new']} new")
    sys.exit(0)
