"""Scheduled secret-scan dispatch.

execute_secret_scan_once must carry SOURCE_TYPE and pass org through to the
runner job (the call previously omitted org and raised TypeError).
"""
from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.secrets import scanner as sec  # noqa: E402


def _patch_execute(monkeypatch, *, sources, job_status="completed", job_error=None):
    created = {}

    def fake_create_job(**kwargs):
        created.update(kwargs)
        return {"id": "job-1"}

    def fake_read_job(_job_id):
        return {"status": job_status, "error": job_error}

    transitions = []

    monkeypatch.setattr(sec, "get_scan_sources_for_org", lambda org: sources)
    monkeypatch.setattr(sec, "read_secret_run", lambda org, run_id: {"id": run_id, "status": "running"})
    monkeypatch.setattr(sec, "create_secret_run", lambda org, run_id: {"id": run_id})
    monkeypatch.setattr(sec, "update_secret_run", lambda org, run_id, patch: None)
    monkeypatch.setattr(sec, "_transition_run",
                        lambda org, run_id, status, patch: transitions.append((status, patch)) or {"status": status})
    monkeypatch.setattr("src.runner.jobs.create_job", fake_create_job)
    monkeypatch.setattr("src.runner.jobs.read_job", fake_read_job)
    return created, transitions


def _src(urls, token=""):
    return SimpleNamespace(repo_urls=urls, token=token)


def test_execute_dispatches_secret_job_with_source_type(monkeypatch):
    created, _ = _patch_execute(monkeypatch, sources=[_src(["https://github.com/acme/api"])])
    sec.execute_secret_scan_once("acme", "tok", "run-1", source_type="github", scanner_config={})
    assert created["job_type"] == "secret_scanning"
    assert created["env_vars"]["SOURCE_TYPE"] == "github"
    assert created["env_vars"]["ORG_LABEL"] == "acme"
    assert "github.com/acme/api" in created["env_vars"]["GIT_REPOS"]


def test_execute_runner_failure_marks_failed(monkeypatch):
    _, transitions = _patch_execute(monkeypatch, sources=[_src(["https://github.com/acme/api"])],
                                    job_status="failed", job_error="boom")
    sec.execute_secret_scan_once("acme", "tok", "run-3", source_type="github", scanner_config={})
    assert any(status == "failed" for status, _ in transitions)
