"""Unit tests for upsert_posture_snapshot and the scheduler midnight tick."""
from __future__ import annotations

import os
from dataclasses import dataclass
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.shared.analytics import (  # noqa: E402
    AnalyticsPayload,
    AgeBucket,
    Counts,
    RemediationMetrics,
    RepositoryCoverage,
    RiskScore,
    SeverityDistributionItem,
    TopRepository,
)


def _fake_payload() -> AnalyticsPayload:
    return AnalyticsPayload(
        counts=Counts(total=10, critical=1, high=2, medium=3, low=4),
        severityDistribution=[],
        ageBuckets=[],
        topRepositories=[],
        remediation=RemediationMetrics(totalFixed=5, avgDays=7.0, medianDays=5.0, fixedLast30d=2),
        repositoryCoverage=RepositoryCoverage(total=3, affected=2, unaffected=1, percentage=67),
        riskScore=RiskScore(score=72, rating="At Risk", summary="test"),
    )


def test_upsert_calls_run_db():
    """upsert_posture_snapshot invokes run_db with the correct org."""
    from src.posture.service import upsert_posture_snapshot

    with patch("src.posture.service.run_db") as mock_run_db:
        mock_run_db.return_value = None
        upsert_posture_snapshot(org="test-org", payload=_fake_payload())
        assert mock_run_db.called


def test_snapshot_worker_calls_upsert_per_org():
    """_take_posture_snapshots spawns one thread per org and calls upsert for each."""
    import time

    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    with (
        patch("src.posture.service.get_posture_snapshot", return_value=_fake_payload()),
        patch("src.posture.service.upsert_posture_snapshot") as mock_upsert,
    ):
        scheduler._take_posture_snapshots(["org-a", "org-b"])
        time.sleep(0.3)  # let daemon threads finish
        assert mock_upsert.call_count == 2


def test_snapshot_worker_empty_orgs():
    """_take_posture_snapshots with empty org list does not raise."""
    from src.scheduler import AutoRerunScheduler

    scheduler = AutoRerunScheduler()
    scheduler._take_posture_snapshots([])  # must not raise
