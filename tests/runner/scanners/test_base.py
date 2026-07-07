"""Tests for the ExecutionResult dataclass and the scanner run_scan contract."""
from __future__ import annotations

from pathlib import Path

from runner.scanners.base import ExecutionResult


def test_execution_result_defaults():
    result = ExecutionResult(exit_code=0, job_dir=Path("/tmp/x"))
    assert result.exit_code == 0
    assert result.job_dir == Path("/tmp/x")
    assert result.log_tail == []


def test_execution_result_with_log_tail():
    result = ExecutionResult(exit_code=1, job_dir=Path("/tmp/x"), log_tail=["a", "b"])
    assert result.log_tail == ["a", "b"]


def test_scanner_run_scan_contract():
    class FakeScanner:
        SCANNER_TYPE = "fake"

        def run_scan(self, job, job_dir, on_progress=None, cancel_event=None):
            return ExecutionResult(exit_code=0, job_dir=job_dir)

    fake = FakeScanner()
    assert hasattr(fake, "SCANNER_TYPE")
    assert hasattr(fake, "run_scan") and callable(fake.run_scan)
    result = fake.run_scan({"jobId": "x"}, Path("/tmp/x"))
    assert isinstance(result, ExecutionResult)
