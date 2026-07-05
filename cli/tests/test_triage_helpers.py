"""Unit tests for aegis_cli.triage_helpers — pure helper functions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from aegis_cli.triage_helpers import (
    apply_filters,
    confirm_bulk_action,
    format_summary,
    parse_duration,
    parse_finding_ids,
)


# ---------------------------------------------------------------------------
# parse_finding_ids
# ---------------------------------------------------------------------------

def test_parse_finding_ids_basic():
    assert parse_finding_ids("F-1,F-2,F-3") == ["F-1", "F-2", "F-3"]


def test_parse_finding_ids_strips_whitespace():
    assert parse_finding_ids("F-1 , F-2 , F-3") == ["F-1", "F-2", "F-3"]


def test_parse_finding_ids_single():
    assert parse_finding_ids("F-42") == ["F-42"]


def test_parse_finding_ids_ignores_empty_segments():
    assert parse_finding_ids("F-1,,F-2, ,F-3") == ["F-1", "F-2", "F-3"]


# ---------------------------------------------------------------------------
# parse_duration
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("30d", 30),
    ("1w", 7),
    ("2w", 14),
    ("1d", 1),
    ("90d", 90),
    ("1h", 1),          # rounds up from 1/24 to 1
    ("24h", 1),         # exactly 1 day
    ("48h", 2),
    ("2.5w", 18),       # ceil(17.5) = 18
    ("1D", 1),          # case insensitive
    ("1W", 7),
    ("1H", 1),
])
def test_parse_duration_valid(raw, expected):
    assert parse_duration(raw) == expected


@pytest.mark.parametrize("raw", [
    "30",       # no unit
    "30m",      # unsupported unit (months / minutes)
    "abc",
    "",
    "-1d",
    "1.2.3d",
])
def test_parse_duration_invalid(raw):
    with pytest.raises(ValueError, match="Cannot parse duration"):
        parse_duration(raw)


# ---------------------------------------------------------------------------
# apply_filters
# ---------------------------------------------------------------------------

def _make_finding(fid: str, created_at: datetime | None) -> dict:
    f: dict = {"id": fid}
    if created_at is not None:
        f["created_at"] = created_at.isoformat()
    return f


def test_apply_filters_no_filter_returns_all():
    now = datetime.now(tz=timezone.utc)
    findings = [
        _make_finding("F-1", now - timedelta(days=100)),
        _make_finding("F-2", now - timedelta(days=10)),
    ]
    assert set(apply_filters(findings)) == {"F-1", "F-2"}


def test_apply_filters_since_excludes_recent():
    now = datetime.now(tz=timezone.utc)
    findings = [
        _make_finding("F-old", now - timedelta(days=100)),
        _make_finding("F-new", now - timedelta(days=10)),
    ]
    result = apply_filters(findings, since="30d")
    assert result == ["F-old"]
    assert "F-new" not in result


def test_apply_filters_since_includes_finding_at_boundary():
    """Findings created exactly at the cutoff (or older) should be included."""
    now = datetime.now(tz=timezone.utc)
    findings = [
        _make_finding("F-boundary", now - timedelta(days=30, seconds=1)),
        _make_finding("F-within", now - timedelta(days=29)),
    ]
    result = apply_filters(findings, since="30d")
    assert "F-boundary" in result
    assert "F-within" not in result


def test_apply_filters_missing_created_at_included():
    """Findings with no timestamp pass through conservatively."""
    findings = [{"id": "F-no-ts"}]
    result = apply_filters(findings, since="30d")
    assert result == ["F-no-ts"]


def test_apply_filters_missing_id_skipped():
    now = datetime.now(tz=timezone.utc)
    findings = [{"title": "no-id-field", "created_at": (now - timedelta(days=100)).isoformat()}]
    assert apply_filters(findings) == []


def test_apply_filters_epoch_timestamp():
    now = datetime.now(tz=timezone.utc)
    old_epoch = (now - timedelta(days=100)).timestamp()
    findings = [{"id": "F-epoch", "created_at": old_epoch}]
    assert apply_filters(findings, since="30d") == ["F-epoch"]


def test_apply_filters_alert_number_fallback():
    """Findings that use 'alert_number' as their ID key should be handled."""
    findings = [{"alert_number": 42}]
    result = apply_filters(findings)
    assert result == ["42"]


# ---------------------------------------------------------------------------
# format_summary
# ---------------------------------------------------------------------------

def test_format_summary_mixed():
    findings = [
        {"security_advisory": {"severity": "critical"}},
        {"security_advisory": {"severity": "critical"}},
        {"security_advisory": {"severity": "high"}},
        {"severity": "medium"},
        {"severity": "low"},
        {"severity": "low"},
    ]
    summary = format_summary(findings)
    assert "critical: 2" in summary
    assert "high: 1" in summary
    assert "medium: 1" in summary
    assert "low: 2" in summary


def test_format_summary_empty():
    assert format_summary([]) == "0 findings"


def test_format_summary_single_severity():
    findings = [{"severity": "high"}, {"severity": "high"}]
    summary = format_summary(findings)
    assert summary == "high: 2"
    assert "critical" not in summary


def test_format_summary_severity_order():
    """Critical should appear before high in the output string."""
    findings = [
        {"severity": "high"},
        {"security_advisory": {"severity": "critical"}},
    ]
    summary = format_summary(findings)
    assert summary.index("critical") < summary.index("high")


# ---------------------------------------------------------------------------
# confirm_bulk_action
# ---------------------------------------------------------------------------

def test_confirm_bulk_action_yes(monkeypatch):
    import click
    monkeypatch.setattr(click, "confirm", lambda *_a, **_kw: True)
    assert confirm_bulk_action(["F-1", "F-2"], action="dismiss") is True


def test_confirm_bulk_action_no(monkeypatch):
    import click
    monkeypatch.setattr(click, "confirm", lambda *_a, **_kw: False)
    assert confirm_bulk_action(["F-1"], action="snooze") is False


def test_confirm_bulk_action_truncates_long_list(capsys, monkeypatch):
    import click
    monkeypatch.setattr(click, "confirm", lambda *_a, **_kw: True)
    targets = [f"F-{i}" for i in range(10)]
    confirm_bulk_action(targets, action="assign")
    captured = capsys.readouterr()
    # Should show ellipsis when more than 5 findings
    assert "…" in captured.out
