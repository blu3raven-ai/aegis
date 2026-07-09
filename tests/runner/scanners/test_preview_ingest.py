"""Code-scanning preview ingest: upload the unverified findings and trigger a
mid-scan ingest so they surface before verification."""
from __future__ import annotations

from pathlib import Path

from runner.scanners.code_scanning.scanner import CodeScanningScanner


class _FakeBackend:
    def __init__(self):
        self.presigned = None
        self.previewed = None

    def presign_uploads(self, job_id, files):
        self.presigned = (job_id, files)
        return {"findings.jsonl": {"url": "http://x/upload", "fields": {}}}

    def preview_ingest(self, job_id):
        self.previewed = job_id


def test_preview_ingest_uploads_then_triggers(tmp_path, monkeypatch):
    findings = tmp_path / "findings.jsonl"
    findings.write_text('{"a":1}\n', encoding="utf-8")
    monkeypatch.setattr(
        "runner.clients.uploader.post_to_url", lambda path, url, fields: "ok"
    )

    s = CodeScanningScanner()
    s._backend = _FakeBackend()
    s._preview_ingest_findings(findings, {"jobId": "job-1"})

    assert s._backend.presigned == ("job-1", ["findings.jsonl"])
    assert s._backend.previewed == "job-1"


def test_preview_ingest_noop_without_backend(tmp_path):
    findings = tmp_path / "findings.jsonl"
    findings.write_text("{}\n", encoding="utf-8")
    s = CodeScanningScanner()
    s._backend = None
    # Must not raise when there is no backend to call.
    s._preview_ingest_findings(findings, {"jobId": "job-1"})


def test_preview_ingest_swallows_upload_failure(tmp_path, monkeypatch):
    findings = tmp_path / "findings.jsonl"
    findings.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        "runner.clients.uploader.post_to_url", lambda path, url, fields: "error"
    )
    s = CodeScanningScanner()
    s._backend = _FakeBackend()
    s._preview_ingest_findings(findings, {"jobId": "job-1"})
    # Upload failed → preview never triggered, and no exception escaped.
    assert s._backend.previewed is None
