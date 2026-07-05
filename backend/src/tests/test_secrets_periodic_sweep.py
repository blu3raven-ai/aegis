"""Tests for periodic_sweep.should_run_periodic_sweep + enqueue_full_history_scan."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


from src.secrets.periodic_sweep import should_run_periodic_sweep, enqueue_full_history_scan

REPO_ID = "acme-org/sweep-test-repo"
DETECTOR_V1 = "trufflehog@3.82.1"
DETECTOR_V2 = "trufflehog@3.83.0"


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── never swept → must sweep ──────────────────────────────────────────────────


def test_never_swept_returns_true():
    assert should_run_periodic_sweep(REPO_ID, None, DETECTOR_V1, None) is True


# ── detector version changed → must sweep ────────────────────────────────────


def test_version_bump_returns_true():
    last_sweep = _now() - timedelta(hours=1)   # very recent
    assert should_run_periodic_sweep(
        REPO_ID, last_sweep, DETECTOR_V2, DETECTOR_V1
    ) is True


def test_same_version_recent_sweep_returns_false():
    last_sweep = _now() - timedelta(hours=1)
    assert should_run_periodic_sweep(
        REPO_ID, last_sweep, DETECTOR_V1, DETECTOR_V1
    ) is False


# ── staleness threshold ───────────────────────────────────────────────────────


def test_sweep_older_than_7_days_returns_true():
    last_sweep = _now() - timedelta(days=8)
    assert should_run_periodic_sweep(
        REPO_ID, last_sweep, DETECTOR_V1, DETECTOR_V1
    ) is True


def test_sweep_exactly_6_days_old_returns_false():
    last_sweep = _now() - timedelta(days=6)
    assert should_run_periodic_sweep(
        REPO_ID, last_sweep, DETECTOR_V1, DETECTOR_V1
    ) is False


# ── force flag ────────────────────────────────────────────────────────────────


def test_force_sweep_overrides_all():
    """force_sweep=True must return True even if everything else is fresh."""
    last_sweep = _now() - timedelta(minutes=5)
    result = should_run_periodic_sweep(
        REPO_ID, last_sweep, DETECTOR_V1, DETECTOR_V1, force_sweep=True
    )
    assert result is True


def test_force_sweep_with_none_last_sweep():
    result = should_run_periodic_sweep(
        REPO_ID, None, DETECTOR_V1, None, force_sweep=True
    )
    assert result is True


# ── version change takes precedence over recency ─────────────────────────────


def test_version_change_trumps_recent_sweep():
    last_sweep = _now() - timedelta(seconds=30)
    result = should_run_periodic_sweep(
        REPO_ID, last_sweep, DETECTOR_V2, DETECTOR_V1
    )
    assert result is True


# ── enqueue stub does not raise ──────────────────────────────────────────────


def test_enqueue_full_history_scan_does_not_raise():
    enqueue_full_history_scan(REPO_ID)


def test_enqueue_full_history_scan_accepts_any_repo_id():
    enqueue_full_history_scan("some-org/some-repo")
    enqueue_full_history_scan("")
