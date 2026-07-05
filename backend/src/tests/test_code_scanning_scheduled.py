"""Scheduled code-scanning dispatch (execute_code_scanning_scan_once).

The scheduled per-tool auto-rerun must carry SOURCE_TYPE so the backend ingest
can resolve each finding's repo asset, and must pass org through to the runner
job (the call previously omitted it and raised TypeError).
"""
from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.code_scanning import scanner as cs  # noqa: E402


def _patch(monkeypatch, *, sources, job_status="completed", job_error=None):
    created = {}

    def fake_create_job(**kwargs):
        created.update(kwargs)
        return {"id": "job-1"}

    def fake_read_job(_job_id):
        return {"status": job_status, "error": job_error}

    patches = {}

    def fake_update(org, run_id, patch):
        patches.setdefault(run_id, []).append(patch)

    monkeypatch.setattr(cs, "get_scan_sources_for_org", lambda org: sources)
    monkeypatch.setattr("src.runner.jobs.create_job", fake_create_job)
    monkeypatch.setattr("src.runner.jobs.read_job", fake_read_job)
    monkeypatch.setattr(cs, "update_code_scanning_run", fake_update)
    return created, patches


def _src(urls, token=""):
    return SimpleNamespace(repo_urls=urls, token=token)


def test_execute_dispatches_code_job_with_source_type(monkeypatch):
    created, _ = _patch(monkeypatch, sources=[_src(["https://github.com/acme/api"])])
    out = cs.execute_code_scanning_scan_once("acme", "tok", "run-1", source_type="github", scanner_config={})
    assert out and out["org"] == "acme"
    assert created["job_type"] == "code_scanning"
    assert created["env_vars"]["SOURCE_TYPE"] == "github"
    assert created["env_vars"]["ORG_LABEL"] == "acme"
    assert "github.com/acme/api" in created["env_vars"]["GIT_REPOS"]


def test_execute_no_sources_completes_without_job(monkeypatch):
    created, patches = _patch(monkeypatch, sources=[])
    out = cs.execute_code_scanning_scan_once("acme", "tok", "run-2", source_type="github", scanner_config={})
    assert out is not None
    assert "job_type" not in created  # no runner job dispatched
    assert any(p.get("status") == "completed" for p in patches["run-2"])


def test_execute_runner_failure_marks_failed(monkeypatch):
    _, patches = _patch(monkeypatch, sources=[_src(["https://github.com/acme/api"])],
                        job_status="failed", job_error="boom")
    out = cs.execute_code_scanning_scan_once("acme", "tok", "run-3", source_type="github", scanner_config={})
    assert out is None
    failed = [p for p in patches["run-3"] if p.get("status") == "failed"]
    assert failed and failed[0]["error"] == "boom"
