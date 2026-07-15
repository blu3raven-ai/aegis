"""Contract tests for shared path / org normalisation helpers.

normalize_org and normalize_path_segment are directory-traversal guards used to
build storage keys from untrusted org names and run ids, so their sanitisation
and rejection behaviour is security-relevant. Also covers the ISO datetime
helpers, CSV org parsing, and the SAFE_RELATIVE_PATH guard.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.shared.paths import (
    SAFE_RELATIVE_PATH,
    dt_to_iso,
    normalize_org,
    normalize_path_segment,
    parse_iso_utc,
    parse_org_values,
)


# ----- normalize_org --------------------------------------------------------

def test_normalize_org_lowercases_and_sanitises():
    assert normalize_org("ACME") == "acme"
    assert normalize_org("Acme Org") == "acme_org"   # space -> _
    assert normalize_org("a/b") == "a_b"             # slash -> _
    assert normalize_org("  acme  ") == "acme"       # trimmed
    assert normalize_org("acme-1.2_x") == "acme-1.2_x"  # _ . - kept


def test_normalize_org_strips_leading_dots():
    assert normalize_org(".acme") == "acme"
    assert normalize_org("..acme") == "acme"


def test_normalize_org_rejects_traversal_and_empty():
    with pytest.raises(ValueError):
        normalize_org("a..b")        # embedded .. survives -> rejected
    with pytest.raises(ValueError):
        normalize_org("...")         # all dots -> empty after lstrip
    with pytest.raises(ValueError):
        normalize_org("")
    with pytest.raises(ValueError):
        normalize_org("   ")


def test_normalize_org_slash_traversal_neutralised():
    # '/' becomes '_', so the classic ../ payload can't form a traversal.
    assert normalize_org("../etc") == "_etc"


# ----- normalize_path_segment ----------------------------------------------

def test_normalize_path_segment_sanitises():
    assert normalize_path_segment("run-123_abc") == "run-123_abc"
    # dots and slashes (traversal chars) are replaced with _
    assert normalize_path_segment("run/../x") == "run____x"
    assert normalize_path_segment("a.b") == "a_b"


def test_normalize_path_segment_rejects_empty():
    with pytest.raises(ValueError):
        normalize_path_segment("")
    with pytest.raises(ValueError):
        normalize_path_segment("   ")


# ----- ISO datetime helpers -------------------------------------------------

def test_parse_iso_utc_handles_z_naive_and_offset():
    assert parse_iso_utc("2026-06-28T12:00:00Z") == datetime(2026, 6, 28, 12, 0, tzinfo=timezone.utc)
    # naive assumed UTC
    assert parse_iso_utc("2026-06-28T12:00:00") == datetime(2026, 6, 28, 12, 0, tzinfo=timezone.utc)
    # offset preserved as the same instant (12:00+02:00 == 10:00Z)
    assert parse_iso_utc("2026-06-28T12:00:00+02:00") == datetime(2026, 6, 28, 10, 0, tzinfo=timezone.utc)


def test_dt_to_iso():
    assert dt_to_iso(None) is None
    assert dt_to_iso(datetime(2026, 6, 28, 12, 0, tzinfo=timezone.utc)) == "2026-06-28T12:00:00.000Z"
    # non-UTC offset is converted to UTC and Z-suffixed
    from datetime import timedelta
    plus2 = timezone(timedelta(hours=2))
    assert dt_to_iso(datetime(2026, 6, 28, 12, 0, tzinfo=plus2)) == "2026-06-28T10:00:00.000Z"


# ----- parse_org_values -----------------------------------------------------

def test_parse_org_values_splits_dedups_case_insensitively():
    assert parse_org_values(["Acme, beta", "ACME", "  ", "gamma"]) == ["Acme", "beta", "gamma"]


# ----- SAFE_RELATIVE_PATH ---------------------------------------------------

def test_safe_relative_path_matches_safe_paths():
    for ok in ("a", "a/b/c", "_x/y", "a.b-c/d_e"):
        assert SAFE_RELATIVE_PATH.match(ok), ok


def test_safe_relative_path_rejects_traversal_and_absolute():
    for bad in ("../x", "/abs", "a//b", "a/..", "", ".hidden/x"):
        assert not SAFE_RELATIVE_PATH.match(bad), bad
