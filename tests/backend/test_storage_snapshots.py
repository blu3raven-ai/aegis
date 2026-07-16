"""Pure-logic coverage for storage.py snapshot builders — the empty/analytics
scaffolding returned to callers with no data, and the secrets snapshot combine."""
from __future__ import annotations

from src.storage import (
    build_secrets_snapshot,
    combine_secrets_snapshots,
    empty_container_scanning_snapshot,
    empty_dependencies_snapshot,
)


def test_empty_dependencies_snapshot_shape():
    snap = empty_dependencies_snapshot("ACME-Org")
    assert snap["meta"]["org"] == "acme-org"  # lowercased
    assert snap["alerts"] == []
    counts = snap["analytics"]["counts"]
    assert counts == {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    sevs = {s["severity"] for s in snap["analytics"]["severityDistribution"]}
    assert sevs == {"critical", "high", "medium", "low"}
    assert snap["analytics"]["riskScore"]["rating"] == "none"


def test_empty_container_snapshot_is_lowercased_and_zeroed():
    snap = empty_container_scanning_snapshot("MyOrg")
    assert snap["meta"]["org"] == "myorg"
    assert isinstance(snap["analytics"], dict)


def test_build_secrets_snapshot_empty_findings():
    snap = build_secrets_snapshot("acme", [], None)
    assert isinstance(snap, dict) and "meta" in snap


def test_combine_secrets_snapshots_empty():
    combined = combine_secrets_snapshots([], [])
    assert isinstance(combined, dict)
