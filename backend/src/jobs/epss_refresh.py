"""FIRST.org EPSS scores refresh job.

This module exposes a single callable, refresh_epss_scores(), which fetches
the current EPSS feed and upserts it into the database.

Wiring options (choose one per deployment):

  1. AutoRerunScheduler (preferred for monolith):
       Add a _trigger_epss_refresh() method to AutoRerunScheduler in
       src/scheduler.py and call it from _tick() at a daily schedule, e.g.
       cron "15 3 * * *" (03:15 UTC, 15 min after the KEV refresh).

  2. External cron / sidecar:
       Call `python -m src.jobs.epss_refresh` directly, or invoke
       refresh_epss_scores() from an admin CLI entrypoint. This module
       is importable with no side effects — the refresh only runs when
       refresh_epss_scores() is explicitly called.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def refresh_epss_scores() -> dict:
    """Fetch the EPSS feed and upsert into the database.

    Designed to be called from a scheduler tick or an admin CLI command.
    Returns a summary dict so callers can log or surface the result.

    Fetch failures are re-raised so the scheduler can decide whether to
    retry — we do not silently swallow transport errors here.
    """
    from src.epss.fetcher import fetch_epss_scores
    from src.epss.service import EpssService

    logger.info("epss_refresh: starting feed fetch")
    rows = fetch_epss_scores()
    logger.info("epss_refresh: fetched %d rows, upserting", len(rows))

    service = EpssService()
    new_count = service.upsert_scores(rows)

    # EPSS percentile flows into risk_score (up to +20) — recompute across
    # orgs so a feed bump propagates to the UI without waiting for a scan.
    from src.db.helpers import run_db
    from src.findings.risk_score import recompute_finding_risk_scores

    async def _rescore(session):
        return await recompute_finding_risk_scores(session)

    rescored = run_db(_rescore)

    logger.info(
        "epss_refresh: done — %d new rows added, %d findings rescored",
        new_count, rescored,
    )
    return {"fetched": len(rows), "new": new_count, "rescored": rescored}


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    result = refresh_epss_scores()
    print(f"EPSS refresh complete: {result['fetched']} rows fetched, {result['new']} new")
    sys.exit(0)
