"""Tests for the premium intel feed (argus.feed) and its wiring to the store."""
from __future__ import annotations

from pathlib import Path

from argus.feed import (
    EmptyFeedSource,
    JsonFileFeedSource,
    default_feed_source,
    fetch_premium_records,
)
from argus.matching import InMemoryPremiumStore, load_premium_store, match_components
from argus.models import MatchComponent

_SAMPLE = Path(__file__).resolve().parents[1] / "matching" / "sample_advisories.json"
_COMPONENT = MatchComponent(purl="pkg:pypi/example-pkg@1.1.0", version="1.1.0")


def test_default_source_is_empty():
    assert isinstance(default_feed_source(), EmptyFeedSource)
    assert default_feed_source().fetch() == []


def test_fetch_default_yields_nothing():
    assert fetch_premium_records() == []


def test_load_premium_store_empty_via_default_feed():
    # The store flows through the default (empty) feed source.
    assert load_premium_store().advisories_for("pypi", "example-pkg") == []


def test_match_path_still_empty_via_default_feed():
    assert match_components("deps", [_COMPONENT]) == []


def test_json_source_loads_records():
    records = JsonFileFeedSource(_SAMPLE).fetch()
    assert len(records) == 1
    assert records[0].package == "example-pkg"
    assert records[0].intel.exploit_maturity == "poc"


def test_store_built_from_feed_source_matches():
    # Swapping the source (the single live-wiring point) flows real records all
    # the way through the matcher.
    store = InMemoryPremiumStore(fetch_premium_records(JsonFileFeedSource(_SAMPLE)))
    hits = match_components("deps", [_COMPONENT], store=store)
    assert len(hits) == 1
    assert hits[0].intel.exploit_maturity == "poc"
