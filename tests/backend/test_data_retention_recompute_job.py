"""Tests for the data retention recompute cron entrypoint."""
from __future__ import annotations

import logging
from unittest.mock import patch

from src.jobs.data_retention_recompute import trigger_data_retention_recompute
from src.rules.data_retention_evaluator import DataRetentionEvalResult


def test_trigger_iterates_all_orgs():
    """Every org_id in the list should be passed to the evaluator exactly once."""
    call_args: list[str] = []

    def fake_evaluate(org_id, **kwargs):
        call_args.append(org_id)
        return DataRetentionEvalResult(
            rules_evaluated=0, scans_checked=0, archived=0, deleted=0,
        )

    with patch(
        "src.rules.data_retention_evaluator.evaluate_data_retention_for_org",
        side_effect=fake_evaluate,
    ):
        trigger_data_retention_recompute(["org-a", "org-b", "org-c"])

    assert call_args == ["org-a", "org-b", "org-c"]


def test_trigger_swallows_per_org_exceptions(caplog):
    """One bad org should be logged but not stop other orgs from running."""
    call_args: list[str] = []

    def fake_evaluate(org_id, **kwargs):
        call_args.append(org_id)
        if org_id == "bad-org":
            raise RuntimeError("boom")
        return DataRetentionEvalResult(
            rules_evaluated=0, scans_checked=0, archived=0, deleted=0,
        )

    with patch(
        "src.rules.data_retention_evaluator.evaluate_data_retention_for_org",
        side_effect=fake_evaluate,
    ):
        trigger_data_retention_recompute(["org-a", "bad-org", "org-c"])

    assert call_args == ["org-a", "bad-org", "org-c"]
    assert any(
        "Data retention recompute failed" in rec.message for rec in caplog.records
    )


def test_trigger_logs_summary_per_org():
    """A successful per-org run should log an info line with the result counts."""

    def fake_evaluate(org_id, **kwargs):
        return DataRetentionEvalResult(
            rules_evaluated=3, scans_checked=12, archived=4, deleted=2,
        )

    with patch(
        "src.rules.data_retention_evaluator.evaluate_data_retention_for_org",
        side_effect=fake_evaluate,
    ):
        logger = logging.getLogger("src.jobs.data_retention_recompute")
        with patch.object(logger, "info") as mock_info:
            trigger_data_retention_recompute(["org-a"])

            assert mock_info.called
            call_args = mock_info.call_args[0]
            call_msg = call_args[0]
            assert "rules=%d" in call_msg
            assert "scans=%d" in call_msg
            assert "archived=%d" in call_msg
            assert "deleted=%d" in call_msg
            # positional args after format string: org_id, rules, scans, archived, deleted
            assert call_args[1] == "org-a"
            assert call_args[2] == 3
            assert call_args[3] == 12
            assert call_args[4] == 4
            assert call_args[5] == 2


def test_trigger_handles_empty_org_list():
    """Empty org list should be a no-op with no exception."""
    with patch(
        "src.rules.data_retention_evaluator.evaluate_data_retention_for_org",
    ) as mock_eval:
        trigger_data_retention_recompute([])
        assert not mock_eval.called


def test_trigger_logs_zero_run_when_no_action_taken():
    """The summary log line is emitted even when archived+deleted=0."""

    def fake_evaluate(org_id, **kwargs):
        return DataRetentionEvalResult(
            rules_evaluated=1, scans_checked=5, archived=0, deleted=0,
        )

    with patch(
        "src.rules.data_retention_evaluator.evaluate_data_retention_for_org",
        side_effect=fake_evaluate,
    ):
        logger = logging.getLogger("src.jobs.data_retention_recompute")
        with patch.object(logger, "info") as mock_info:
            trigger_data_retention_recompute(["org-a"])

            assert mock_info.called
            call_args = mock_info.call_args[0]
            assert call_args[4] == 0
            assert call_args[5] == 0
