"""Tests for the scanner coverage recompute cron entrypoint."""
from __future__ import annotations

from unittest.mock import patch

from src.jobs.scanner_coverage_recompute import trigger_scanner_coverage_recompute


def test_failing_org_does_not_block_subsequent_orgs(caplog):
    """One bad org should be logged but not stop other orgs from running."""
    call_args: list[str] = []

    def fake_evaluate(org_id, **kwargs):
        call_args.append(org_id)
        if org_id == "bad-org":
            raise RuntimeError("boom")
        from src.rules.scanner_coverage_evaluator import ScannerCoverageEvalResult
        return ScannerCoverageEvalResult(
            rules_evaluated=0, repos_checked=0,
            violations_opened=0, violations_resolved=0,
            stale_alerts_dispatched=0,
        )

    with patch(
        "src.rules.scanner_coverage_evaluator.evaluate_scanner_coverage_for_org",
        side_effect=fake_evaluate,
    ):
        trigger_scanner_coverage_recompute(["org-a", "bad-org", "org-c"])

    assert call_args == ["org-a", "bad-org", "org-c"]
    assert any("Scanner coverage recompute failed" in rec.message for rec in caplog.records)


def test_logs_summary_per_org():
    """A successful per-org run should log an info line with the result counts."""
    from src.rules.scanner_coverage_evaluator import ScannerCoverageEvalResult

    def fake_evaluate(org_id, **kwargs):
        return ScannerCoverageEvalResult(
            rules_evaluated=2, repos_checked=5,
            violations_opened=1, violations_resolved=0,
            stale_alerts_dispatched=1,
        )

    import logging
    with patch(
        "src.rules.scanner_coverage_evaluator.evaluate_scanner_coverage_for_org",
        side_effect=fake_evaluate,
    ):
        logger = logging.getLogger("src.jobs.scanner_coverage_recompute")
        with patch.object(logger, "info") as mock_info:
            trigger_scanner_coverage_recompute(["org-a"])
            assert mock_info.called
            call_msg = mock_info.call_args[0][0]
            assert "rules=%d" in call_msg
            assert "stale_alerts=%d" in call_msg
