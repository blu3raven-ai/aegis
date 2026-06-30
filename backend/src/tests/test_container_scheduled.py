"""Scheduled container-scan dispatch (execute_container_scan_once).

The scheduled per-tool auto-rerun must carry SOURCE_TYPE so the backend ingest
can resolve each image asset (source_type was never threaded through
execute -> _run_full_or_sbom -> _execute_via_runner before).
"""
from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.containers import scanner as ct  # noqa: E402


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

    monkeypatch.setattr(ct, "get_scan_sources_for_org", lambda org: sources)
    monkeypatch.setattr(ct, "_get_previous_digests", lambda org: {})
    monkeypatch.setattr("src.runner.jobs.create_job", fake_create_job)
    monkeypatch.setattr("src.runner.jobs.read_job", fake_read_job)
    monkeypatch.setattr(ct, "update_container_scanning_run", fake_update)
    return created, patches


def _src(images, token=""):
    return SimpleNamespace(container_images=images, registry_token=token, registry_username="")


def test_execute_dispatches_container_job_with_source_type(monkeypatch):
    created, _ = _patch(monkeypatch, sources=[_src(["ghcr.io/acme/app:1.0"])])
    ct.execute_container_scan_once("acme", None, "run-1", source_type="ghcr", scanner_config={})
    assert created["job_type"] == "container_scanning"
    assert created["env_vars"]["SOURCE_TYPE"] == "ghcr"
    assert "ghcr.io/acme/app:1.0" in created["env_vars"]["DOCKER_IMAGES"]


def test_execute_no_images_marks_failed(monkeypatch):
    created, patches = _patch(monkeypatch, sources=[])
    ct.execute_container_scan_once("acme", None, "run-2", source_type="ghcr", scanner_config={})
    assert "job_type" not in created  # no runner job dispatched
    assert any(p.get("status") == "failed" for p in patches["run-2"])


def test_execute_runner_failure_marks_failed(monkeypatch):
    _, patches = _patch(monkeypatch, sources=[_src(["ghcr.io/acme/app:1.0"])],
                        job_status="failed", job_error="boom")
    ct.execute_container_scan_once("acme", None, "run-3", source_type="ghcr", scanner_config={})
    assert any(p.get("status") == "failed" for p in patches["run-3"])
