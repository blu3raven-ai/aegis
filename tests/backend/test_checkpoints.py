"""Tests for shared checkpoint utilities."""
from datetime import datetime, timezone, timedelta
from src.shared.checkpoints import compute_coverage_gaps


def test_compute_coverage_gaps_missing_checkpoint():
    """Repos with no checkpoint show as missing."""
    gaps = compute_coverage_gaps(
        tool="dependencies",
        org="testorg",
        expected_repos=["org/repo-a", "org/repo-b"],
    )
    assert len(gaps) == 2
    assert gaps[0]["reason"] == "missing_checkpoint"
    assert gaps[1]["reason"] == "missing_checkpoint"


def test_compute_coverage_gaps_empty_expected():
    """No expected repos = no gaps."""
    gaps = compute_coverage_gaps(
        tool="dependencies",
        org="testorg",
        expected_repos=[],
    )
    assert gaps == []
