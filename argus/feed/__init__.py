"""Premium intel feed — the freshness flywheel that fills the match store.

This is the ingestion layer for the premium advisory data. The matcher's
``load_premium_store`` pulls its records from here, so the *entire* match
pipeline is wired end-to-end; the only placeholder is the feed SOURCE.

To take Argus premium live, implement a real ``PremiumFeedSource`` (vendor
threat-intel plus the enrichment that derives exploit maturity / affected
functions / reputation / the alias graph) and return it from
``default_feed_source``. Nothing else in the match path changes. Until then the
default source yields nothing, so ``/v1/match`` stays empty and the free OSV
match is unaffected.
"""
from __future__ import annotations

from argus.feed.refresh import (
    RefreshState,
    default_feed_source,
    fetch_premium_records,
    run_refresh,
)
from argus.feed.sources import (
    EmptyFeedSource,
    JsonFileFeedSource,
    PremiumFeedSource,
)

__all__ = [
    "fetch_premium_records",
    "default_feed_source",
    "run_refresh",
    "RefreshState",
    "PremiumFeedSource",
    "EmptyFeedSource",
    "JsonFileFeedSource",
]
