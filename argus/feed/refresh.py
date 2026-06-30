"""The flywheel entrypoint: pull premium records from the configured source.

``fetch_premium_records`` is what the match store calls to populate itself, so
the whole match pipeline is wired end-to-end. ``default_feed_source`` is the
single swap point — return a real ``PremiumFeedSource`` there to go live.

``run_refresh`` is the operational side of the flywheel: a scheduler calls it on
an interval to pull only what changed since the last run (the cursor) and upsert
it into the store. Freshness is the moat, so this is what keeps it sharp.
"""
from __future__ import annotations

import logging

from pydantic import BaseModel

from argus.feed.sources import EmptyFeedSource, PremiumFeedSource
from argus.matching.models import PremiumAdvisoryRecord
from argus.matching.store import InMemoryPremiumStore

logger = logging.getLogger(__name__)


def default_feed_source() -> PremiumFeedSource:
    """Return the premium feed source.

    THE SWAP POINT. Placeholder: ``EmptyFeedSource`` yields nothing, so the store
    stays empty and the free OSV match is unaffected. Return the real premium
    source here to take Argus live — nothing else in the match path changes.
    """
    return EmptyFeedSource()


def fetch_premium_records(
    source: PremiumFeedSource | None = None, *, since: str | None = None
) -> list[PremiumAdvisoryRecord]:
    """Fetch premium advisory records from ``source`` (default: the configured one)."""
    source = source or default_feed_source()
    records = source.fetch(since)
    logger.info("argus premium feed: fetched %d record(s)", len(records))
    return records


class RefreshState(BaseModel):
    """The flywheel's progress: what to pull next and how fresh the store is.

    ``cursor`` is the watermark passed to the source's ``fetch(since=...)`` so the
    next run pulls only newer records. ``last_synced`` and ``records`` are for
    observability (freshness, store size). Persist this between runs.
    """

    cursor: str | None = None
    last_synced: str | None = None
    records: int = 0


def run_refresh(
    *,
    synced_at: str,
    source: PremiumFeedSource | None = None,
    store: InMemoryPremiumStore | None = None,
    state: RefreshState | None = None,
) -> tuple[InMemoryPremiumStore, RefreshState]:
    """Pull records changed since the last cursor and upsert them into the store.

    Returns the updated ``(store, state)``. A scheduler calls this on an interval,
    passing ``synced_at`` (the current timestamp — kept a parameter so the clock
    stays out of this module and runs are reproducible) and threading the prior
    ``state`` back in. In production the store is the persistent backend that
    ``load_premium_store`` reads from, so a refresh is immediately visible to
    ``/v1/match``; the in-memory store here demonstrates the same contract.
    """
    source = source or default_feed_source()
    store = store if store is not None else InMemoryPremiumStore()
    state = state or RefreshState()

    fetched = source.fetch(state.cursor)
    store.upsert(fetched)
    logger.info(
        "argus premium refresh: upserted %d record(s); store now holds %d",
        len(fetched),
        store.count(),
    )
    return store, RefreshState(
        cursor=synced_at, last_synced=synced_at, records=store.count()
    )
