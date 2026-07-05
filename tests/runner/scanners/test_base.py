"""Tests for BaseScanner protocol + ExecutionResult dataclass."""
from __future__ import annotations

import threading
from pathlib import Path

from runner.scanners.base import BaseScanner, ExecutionResult


def test_execution_result_defaults():
    result = ExecutionResult(exit_code=0, job_dir=Path("/tmp/x"))
    assert result.exit_code == 0
    assert result.job_dir == Path("/tmp/x")
    assert result.log_tail == []


def test_execution_result_with_log_tail():
    result = ExecutionResult(exit_code=1, job_dir=Path("/tmp/x"), log_tail=["a", "b"])
    assert result.log_tail == ["a", "b"]


def test_base_scanner_is_runtime_checkable_protocol():
    class FakeScanner:
        SCANNER_TYPE = "fake"

        def run_scan(self, job, job_dir, on_progress=None, cancel_event=None):
            return ExecutionResult(exit_code=0, job_dir=job_dir)

    fake = FakeScanner()
    assert hasattr(fake, "SCANNER_TYPE")
    assert callable(fake.run_scan)
    result = fake.run_scan({"jobId": "x"}, Path("/tmp/x"))
    assert isinstance(result, ExecutionResult)
