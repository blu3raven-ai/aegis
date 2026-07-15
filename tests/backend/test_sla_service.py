"""Tests for SlaService: deadline math, breach detection, recompute, breach summary."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch


from src.sla.policy import SlaPolicy
from src.sla.service import SlaService


def _finding(
    id: int = 1,
    severity: str = "critical",
    state: str = "open",
    first_seen_at: datetime | None = None,
) -> SimpleNamespace:
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        id=id,
        org="acme-org",
        severity=severity,
        state=state,
        first_seen_at=first_seen_at or now,
    )


def _policy(severity="critical", deadline_days=7, enabled=True) -> SlaPolicy:
    return SlaPolicy(severity=severity, deadline_days=deadline_days, enabled=enabled)


class TestComputeFindingStatus:
    def setup_method(self):
        self.svc = SlaService()

    def test_no_policy_means_no_breach(self):
        finding = _finding()
        result = self.svc.compute_finding_status(finding, None)
        assert result["breached"] is False
        assert result["deadline_at"] is None
        assert result["breach_age_days"] is None

    def test_disabled_policy_means_no_breach(self):
        finding = _finding()
        policy = _policy(enabled=False)
        result = self.svc.compute_finding_status(finding, policy)
        assert result["breached"] is False

    def test_not_breached_when_inside_deadline(self):
        now = datetime.now(timezone.utc)
        finding = _finding(first_seen_at=now - timedelta(days=3))
        policy = _policy(deadline_days=7)
        result = self.svc.compute_finding_status(finding, policy)
        assert result["breached"] is False
        assert result["breach_age_days"] is None

    def test_breached_when_past_deadline(self):
        now = datetime.now(timezone.utc)
        # First seen 10 days ago, deadline is 7 days — 3 days past
        finding = _finding(first_seen_at=now - timedelta(days=10))
        policy = _policy(deadline_days=7)
        result = self.svc.compute_finding_status(finding, policy)
        assert result["breached"] is True
        assert result["breach_age_days"] == 3

    def test_deadline_at_is_first_seen_plus_deadline_days(self):
        first_seen = datetime(2026, 1, 1, tzinfo=timezone.utc)
        finding = _finding(first_seen_at=first_seen)
        policy = _policy(deadline_days=14)
        result = self.svc.compute_finding_status(finding, policy)
        expected = first_seen + timedelta(days=14)
        assert result["deadline_at"] == expected

    def test_naive_datetime_treated_as_utc(self):
        # Naive datetimes should not raise; treated as UTC
        first_seen = datetime(2020, 1, 1)  # no tzinfo
        finding = _finding(first_seen_at=first_seen)
        policy = _policy(deadline_days=1)
        result = self.svc.compute_finding_status(finding, policy)
        assert result["breached"] is True


class TestRecomputeOrg:
    def test_recompute_returns_count(self):
        svc = SlaService()

        now = datetime.now(timezone.utc)
        findings = [
            _finding(id=1, severity="critical", first_seen_at=now - timedelta(days=10)),
            _finding(id=2, severity="high", first_seen_at=now - timedelta(days=5)),
        ]

        mock_policies = [
            {"severity": "critical", "deadline_days": 7, "enabled": True},
            {"severity": "high", "deadline_days": 14, "enabled": True},
            {"severity": "medium", "deadline_days": 30, "enabled": True},
            {"severity": "low", "deadline_days": 90, "enabled": True},
        ]

        with patch.object(svc, "get_policies", return_value=mock_policies), \
             patch("src.sla.service.run_db") as mock_run_db:

            call_count = [0]

            def side_effect(coro_fn):
                call_count[0] += 1
                if call_count[0] == 1:
                    return findings
                return None

            mock_run_db.side_effect = side_effect
            count = svc.recompute(asset_ids=["asset-1"])
            assert count == 2


class TestGetBreachSummary:
    def test_breach_summary_aggregates_correctly(self):
        svc = SlaService()

        # 2 critical open (1 breached), 1 high open (0 breached)
        fake_rows = [
            ("critical", True),
            ("critical", False),
            ("high", False),
        ]

        with patch("src.sla.service.run_db", return_value=fake_rows):
            summary = svc.get_breach_summary(asset_ids=["asset-1"])

        assert summary["critical"]["open"] == 2
        assert summary["critical"]["breached"] == 1
        assert summary["critical"]["breached_pct"] == 0.5
        assert summary["high"]["open"] == 1
        assert summary["high"]["breached"] == 0
        assert summary["medium"]["open"] == 0
        assert summary["low"]["open"] == 0

    def test_breach_pct_zero_when_no_open(self):
        svc = SlaService()
        with patch("src.sla.service.run_db", return_value=[]):
            summary = svc.get_breach_summary(asset_ids=["asset-1"])
        for sev in ("critical", "high", "medium", "low"):
            assert summary[sev]["breached_pct"] == 0.0
