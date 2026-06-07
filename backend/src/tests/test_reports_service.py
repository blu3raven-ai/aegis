from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

import pytest  # noqa: E402

from src.reports.service import generate_report  # noqa: E402


def _fake_report(report_id: int = 1) -> MagicMock:
    row = MagicMock()
    row.id = report_id
    return row


def test_generate_findings_json_report():
    fake_findings = [
        {"id": 1, "tool": "dependencies", "org": "test-org", "repo": "repo1",
         "severity": "high", "state": "open", "title": "CVE-2024-XXXX",
         "identity_key": "k1", "cve_id": "CVE-2024-XXXX",
         "first_seen_at": None, "last_seen_at": None},
    ]

    call_order = []
    def fake_run_db(fn):
        call_order.append("run_db")
        if len(call_order) == 1:
            return fake_findings
        if len(call_order) == 2:
            return 42
        return _fake_report(42)

    with (
        patch("src.reports.service.run_db", side_effect=fake_run_db),
        patch("src.reports.service.upload_bytes") as mock_upload,
    ):
        result = generate_report(
            org="test-org",
            report_type="findings",
            fmt="json",
            title=None,
            filters=None,
            created_by="tester@example.com",
        )

    assert mock_upload.call_count == 1
    kwargs = mock_upload.call_args.kwargs
    assert kwargs["key"] == "test-org/42.json"
    assert kwargs["content_type"] == "application/json"
    assert kwargs["bucket"] == "reports"
    assert b"CVE-2024-XXXX" in kwargs["data"]
    assert result is not None


def test_generate_posture_report():
    from dataclasses import dataclass

    @dataclass
    class _FakePayload:
        critical: int = 1
        high: int = 2

    call_order = []
    def fake_run_db(fn):
        call_order.append("run_db")
        if len(call_order) == 1:
            return 7
        return _fake_report(7)

    with (
        patch("src.posture.service.get_posture_snapshot", return_value=_FakePayload()),
        patch("src.reports.service.run_db", side_effect=fake_run_db),
        patch("src.reports.service.upload_bytes") as mock_upload,
    ):
        generate_report(
            org="test-org",
            report_type="posture",
            fmt="json",
            title="Custom title",
            filters=None,
            created_by="tester@example.com",
        )

    kwargs = mock_upload.call_args.kwargs
    assert kwargs["bucket"] == "reports"
    assert kwargs["content_type"] == "application/json"
    assert kwargs["key"] == "test-org/7.json"
    assert b'"critical": 1' in kwargs["data"]


def test_generate_report_upload_failure_marks_failed_and_raises():
    fake_findings: list[dict] = []
    call_log: list[str] = []

    def fake_run_db(fn):
        # First call: fetch findings (returns empty list)
        # Second call: insert (returns report_id)
        # Third call: mark failed
        call_log.append("run_db")
        if len(call_log) == 1:
            return fake_findings
        if len(call_log) == 2:
            return 99
        return None

    with (
        patch("src.reports.service.run_db", side_effect=fake_run_db),
        patch("src.reports.service.upload_bytes", side_effect=RuntimeError("S3 down")),
    ):
        with pytest.raises(RuntimeError, match="S3 down"):
            generate_report(
                org="test-org",
                report_type="findings",
                fmt="json",
                title=None,
                filters=None,
                created_by="tester@example.com",
            )

    assert len(call_log) == 3, "expected fetch -> insert -> mark_failed run_db calls"
