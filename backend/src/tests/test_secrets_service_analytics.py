"""Contract tests for secret-scan remediation analytics.

`_parse_iso_datetime` normalises mixed ISO formats to UTC (or None); the only
findings that count as "fixed" are reviewStatus false_positive / action_taken,
and resolution velocity is derived from detected->resolved deltas. Timestamps
are built relative to now so the 30-day-window assertions stay deterministic.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.secrets.service_analytics import _parse_iso_datetime, compute_remediation_metrics


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _fixed(*, ago_days: float, duration_days: float, status: str = "action_taken") -> dict:
    now = datetime.now(timezone.utc)
    resolved = now - timedelta(days=ago_days)
    detected = resolved - timedelta(days=duration_days)
    return {"reviewStatus": status, "resolvedAt": _iso(resolved), "detectedAt": _iso(detected)}


# ----- _parse_iso_datetime --------------------------------------------------

def test_parse_iso_z_and_offset_normalise_to_utc():
    assert _parse_iso_datetime("2026-06-28T12:00:00Z") == datetime(2026, 6, 28, 12, 0, tzinfo=timezone.utc)
    assert _parse_iso_datetime("2026-06-28T12:00:00+00:00") == datetime(2026, 6, 28, 12, 0, tzinfo=timezone.utc)
    # +02:00 wall time is 10:00 UTC.
    assert _parse_iso_datetime("2026-06-28T12:00:00+02:00") == datetime(2026, 6, 28, 10, 0, tzinfo=timezone.utc)


def test_parse_iso_naive_assumed_utc():
    parsed = _parse_iso_datetime("2026-06-28T12:00:00")
    assert parsed == datetime(2026, 6, 28, 12, 0, tzinfo=timezone.utc)
    assert parsed.tzinfo is timezone.utc


def test_parse_iso_invalid_inputs_return_none():
    for bad in (None, "", "   ", "not-a-date", 12345):
        assert _parse_iso_datetime(bad) is None


# ----- compute_remediation_metrics ------------------------------------------

def test_empty_yields_nulls_and_zeros():
    m = compute_remediation_metrics([])
    assert m == {"medianDays": None, "avgDays": None, "fixedLast30d": 0, "totalFixed": 0}


def test_only_fixed_statuses_count():
    findings = [
        {"reviewStatus": "new"},
        {"reviewStatus": "pending"},
        _fixed(ago_days=5, duration_days=4, status="false_positive"),
        _fixed(ago_days=5, duration_days=4, status="action_taken"),
    ]
    m = compute_remediation_metrics(findings)
    assert m["totalFixed"] == 2  # only the two fixed statuses


def test_median_and_avg_from_durations():
    findings = [
        _fixed(ago_days=1, duration_days=2),
        _fixed(ago_days=1, duration_days=6),
    ]
    m = compute_remediation_metrics(findings)
    assert m["medianDays"] == 4.0
    assert m["avgDays"] == 4.0


def test_fixed_last_30d_window():
    findings = [
        _fixed(ago_days=5, duration_days=1),     # within 30d
        _fixed(ago_days=100, duration_days=1),   # outside 30d
    ]
    m = compute_remediation_metrics(findings)
    assert m["fixedLast30d"] == 1
    assert m["totalFixed"] == 2


def test_fixed_without_timestamps_counts_in_total_only():
    findings = [
        _fixed(ago_days=2, duration_days=3),
        {"reviewStatus": "action_taken"},  # no resolvedAt/detectedAt
    ]
    m = compute_remediation_metrics(findings)
    assert m["totalFixed"] == 2
    assert m["medianDays"] == 3.0  # only the timestamped finding contributes a duration


def test_negative_duration_is_clamped_to_zero():
    now = datetime.now(timezone.utc)
    resolved = now - timedelta(days=5)
    detected = resolved + timedelta(days=3)  # detected AFTER resolved (clock skew)
    m = compute_remediation_metrics([
        {"reviewStatus": "action_taken", "resolvedAt": _iso(resolved), "detectedAt": _iso(detected)},
    ])
    assert m["medianDays"] == 0.0
