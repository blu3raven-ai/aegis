from __future__ import annotations

from src.containers.tag_recommendation import select_newer_tags


def test_picks_strictly_newer_same_flavour_highest_first():
    tags = ["1.2.0", "1.2.3", "1.2.4", "1.3.0", "2.0.0", "1.2.3"]
    assert select_newer_tags("1.2.3", tags) == ["2.0.0", "1.3.0", "1.2.4"]


def test_respects_limit():
    tags = ["1.1", "1.2", "1.3", "1.4", "1.5"]
    assert select_newer_tags("1.0", tags, limit=2) == ["1.5", "1.4"]


def test_flavour_must_match_exactly():
    # A stable tag never matches an -alpine or -rc tag, and vice-versa.
    tags = ["1.3.0-alpine", "1.3.0", "1.4.0-alpine", "1.4.0-rc1"]
    assert select_newer_tags("1.2.0", tags) == ["1.3.0"]
    assert select_newer_tags("1.2.0-alpine", tags) == ["1.4.0-alpine", "1.3.0-alpine"]


def test_strips_leading_v():
    assert select_newer_tags("v1.2.0", ["v1.2.1", "v1.3.0"]) == ["v1.3.0", "v1.2.1"]


def test_unparseable_current_tag_yields_nothing():
    assert select_newer_tags("latest", ["1.0.0", "2.0.0"]) == []
    assert select_newer_tags("bookworm", ["1.0.0"]) == []
    assert select_newer_tags(None, ["1.0.0"]) == []


def test_ignores_unparseable_candidates():
    assert select_newer_tags("1.0.0", ["latest", "stable", "1.5.0", "garbage"]) == ["1.5.0"]


def test_no_newer_returns_empty():
    assert select_newer_tags("9.9.9", ["1.0.0", "2.0.0"]) == []


def test_numeric_compare_not_lexical():
    # "1.10.0" must sort above "1.9.0" (int compare, not string).
    assert select_newer_tags("1.8.0", ["1.9.0", "1.10.0"]) == ["1.10.0", "1.9.0"]
