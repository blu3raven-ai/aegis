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

  3. --refresh-kev CLI flag:
       See cli/aegis_cli/commands/kev.py `aegis kev refresh` (admin).
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
    new_count = service.upsert_catalog(entries)

    logger.info("kev_refresh: done — %d new entries added", new_count)
    return {"fetched": len(entries), "new": new_count}


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    result = refresh_kev_catalog()
    print(f"KEV refresh complete: {result['fetched']} entries fetched, {result['new']} new")
    sys.exit(0)
