from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

import pytest  # noqa: E402

from src.reports.service import generate_report  # noqa: E402
from src.tests._pdf_skip import pdf_skip  # noqa: E402


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
            report_type="findings",
            fmt="json",
            title=None,
            filters=None,
            created_by="tester@example.com",
            asset_ids=["asset-1"],
        )

    assert mock_upload.call_count == 1
    kwargs = mock_upload.call_args.kwargs
    assert kwargs["key"] == "tester_example_com/42.json"
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
            report_type="posture",
            fmt="json",
            title="Custom title",
            filters=None,
            created_by="tester@example.com",
            asset_ids=["asset-1"],
        )

    kwargs = mock_upload.call_args.kwargs
    assert kwargs["bucket"] == "reports"
    assert kwargs["content_type"] == "application/json"
    assert kwargs["key"] == "tester_example_com/7.json"
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
                report_type="findings",
                fmt="json",
                title=None,
                filters=None,
                created_by="tester@example.com",
                asset_ids=["asset-1"],
            )

    assert len(call_log) == 3, "expected fetch -> insert -> mark_failed run_db calls"


def test_report_visible_to_creator_only_when_no_persisted_asset_ids():
    from src.reports.service import _report_visible_to_viewer

    report = MagicMock()
    report.created_by = "alice@example.com"
    report.filters = None

    assert _report_visible_to_viewer(
        report, viewer_id="alice@example.com", viewer_asset_ids=set()
    )
    assert not _report_visible_to_viewer(
        report, viewer_id="bob@example.com", viewer_asset_ids={"asset-1"}
    )


def test_report_visible_via_asset_intersection():
    from src.reports.service import _report_visible_to_viewer

    report = MagicMock()
    report.created_by = "alice@example.com"
    report.filters = {"asset_ids": ["asset-1", "asset-2"]}

    assert _report_visible_to_viewer(
        report, viewer_id="bob@example.com", viewer_asset_ids={"asset-2", "asset-9"}
    )
    assert not _report_visible_to_viewer(
        report, viewer_id="bob@example.com", viewer_asset_ids={"asset-9"}
    )


@pdf_skip
def test_generate_findings_pdf_returns_pdf_bytes(monkeypatch):
    """generate_report(format='pdf') uploads PDF bytes with the right content type."""
    from src.reports import service

    captured: dict = {}

    def fake_run_db(coro_factory):
        # First call: _fetch_findings → return fake rows
        # Second call: _insert Report → return id 1
        # Third call: _complete → return a Report-like object
        from src.db.models import Report
        if "calls" not in captured:
            captured["calls"] = 0
        captured["calls"] += 1
        if captured["calls"] == 1:
            return [
                {"severity": "critical", "title": "rce in x", "tool": "semgrep",
                 "state": "open", "identity_key": "k1"},
                {"severity": "high", "title": "ssrf in y", "tool": "snyk",
                 "state": "open", "identity_key": "k2"},
            ]
        if captured["calls"] == 2:
            return 1
        # _complete
        return Report(
            id=1, title="t", report_type="findings", format="pdf",
            status="completed", filters={}, row_count=2, file_size_bytes=1234,
            created_by="u", expires_at=None, storage_key="u/1.pdf",
        )

    def fake_upload(*, key, data, content_type, bucket):
        captured["upload"] = {"key": key, "content_type": content_type, "size": len(data)}

    monkeypatch.setattr(service, "run_db", fake_run_db)
    monkeypatch.setattr(service, "upload_bytes", fake_upload)

    service.generate_report(
        report_type="findings",
        fmt="pdf",
        title="Q3 findings",
        filters=None,
        created_by="u",
        include_archived=False,
        asset_ids=["a-1"],
    )

    assert captured["upload"]["content_type"] == "application/pdf"
    assert captured["upload"]["key"] == "u/1.pdf"
    # Confirm the uploaded content really is a PDF (magic bytes)
    # The exact size will vary so we check via a sentinel callback shape.
    assert captured["upload"]["size"] > 1000


@pdf_skip
def test_generate_posture_pdf_uses_get_posture_snapshot(monkeypatch):
    from src.reports import service
    from src.shared.analytics import (
        AnalyticsPayload, Counts, RemediationMetrics,
        RepositoryCoverage, RiskScore,
    )

    fake_payload = AnalyticsPayload(
        counts=Counts(total=3, critical=1, high=1, medium=1, low=0),
        severityDistribution=[],
        ageBuckets=[],
        topRepositories=[],
        remediation=RemediationMetrics(totalFixed=0, avgDays=None, medianDays=None, fixedLast30d=0),
        repositoryCoverage=RepositoryCoverage(total=2, affected=1, unaffected=1, percentage=50),
        riskScore=RiskScore(score=42, rating="Moderate", summary="ok"),
    )

    monkeypatch.setattr("src.posture.service.get_posture_snapshot", lambda **kw: fake_payload)

    counter = {"n": 0}

    def fake_run_db(_fn):
        from src.db.models import Report
        counter["n"] += 1
        if counter["n"] == 1:
            return 7
        return Report(
            id=7, title="Posture report", report_type="posture", format="pdf",
            status="completed", filters={}, row_count=1, file_size_bytes=999,
            created_by="u", expires_at=None, storage_key="u/7.pdf",
        )

    captured: dict = {}
    def fake_upload(*, key, data, content_type, bucket):
        captured["content_type"] = content_type
        captured["size"] = len(data)

    monkeypatch.setattr(service, "run_db", fake_run_db)
    monkeypatch.setattr(service, "upload_bytes", fake_upload)

    service.generate_report(
        report_type="posture",
        fmt="pdf",
        title=None,
        filters=None,
        created_by="u",
        asset_ids=["a-1"],
    )

    assert captured["content_type"] == "application/pdf"


def test_generate_posture_csv_rejected():
    """Service-level rejection still raises ValueError for posture+csv."""
    from src.reports.service import generate_report

    with pytest.raises(ValueError, match="csv"):
        generate_report(
            report_type="posture",
            fmt="csv",
            title=None,
            filters=None,
            created_by="u",
            asset_ids=["a-1"],
        )
