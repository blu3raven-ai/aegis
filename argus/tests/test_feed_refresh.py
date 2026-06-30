"""Tests for the incremental feed refresh job (the flywheel's operational side)."""
from __future__ import annotations

from argus.feed import RefreshState, run_refresh
from argus.matching import match_components
from argus.matching.models import PremiumAdvisoryRecord, VulnerableRange
from argus.models import MatchAdvisory, MatchComponent


class _CursorSource:
    """A fake incremental source: records keyed by the cursor it's asked for."""

    def __init__(self, by_cursor):
        self._by_cursor = by_cursor
        self.calls = []

    def fetch(self, since=None, org_id=None):
        self.calls.append(since)
        return list(self._by_cursor.get(since, []))


def _record(package, advisory_id, fixed="2.0.0"):
    return PremiumAdvisoryRecord(
        ecosystem="PyPI",
        package=package,
        advisory=MatchAdvisory(id=advisory_id, severity="high"),
        ranges=[VulnerableRange(introduced="0", fixed=fixed)],
    )


def test_first_run_uses_no_cursor_and_populates():
    source = _CursorSource({None: [_record("django", "GHSA-1")]})
    store, state = run_refresh(synced_at="2026-06-29T00:00:00Z", source=source)

    assert source.calls == [None]
    assert store.count() == 1
    assert state.cursor == "2026-06-29T00:00:00Z"
    assert state.last_synced == "2026-06-29T00:00:00Z"
    assert state.records == 1


def test_second_run_pulls_from_cursor_and_upserts():
    source = _CursorSource(
        {
            None: [_record("django", "GHSA-1")],
            "2026-06-29T00:00:00Z": [_record("flask", "GHSA-2")],
        }
    )
    store, state = run_refresh(synced_at="2026-06-29T00:00:00Z", source=source)
    store, state = run_refresh(
        synced_at="2026-06-29T01:00:00Z", source=source, store=store, state=state
    )

    # Second run asked the source for changes since the first cursor.
    assert source.calls == [None, "2026-06-29T00:00:00Z"]
    assert store.count() == 2
    assert state.cursor == "2026-06-29T01:00:00Z"


def test_upsert_replaces_same_advisory_id():
    source = _CursorSource(
        {
            None: [_record("django", "GHSA-1", fixed="2.0.0")],
            "t1": [_record("django", "GHSA-1", fixed="2.0.1")],  # updated fix
        }
    )
    store, state = run_refresh(synced_at="t1", source=source)
    store, state = run_refresh(synced_at="t2", source=source, store=store, state=state)

    advisories = store.advisories_for("PyPI", "django")
    assert len(advisories) == 1  # replaced, not duplicated
    assert advisories[0].ranges[0].fixed == "2.0.1"


def test_refreshed_store_feeds_the_matcher():
    source = _CursorSource({None: [_record("django", "GHSA-1", fixed="4.2.1")]})
    store, _ = run_refresh(synced_at="t1", source=source)

    comp = MatchComponent(purl="pkg:pypi/django@4.2.0", version="4.2.0")
    assert len(match_components("deps", [comp], store=store)) == 1


def test_default_refresh_is_empty_and_honest():
    # No source configured -> the placeholder feed yields nothing.
    store, state = run_refresh(synced_at="t1")
    assert store.count() == 0
    assert state.records == 0


def test_refresh_state_round_trips():
    state = RefreshState(cursor="t1", last_synced="t1", records=3)
    assert RefreshState.model_validate(state.model_dump()) == state
