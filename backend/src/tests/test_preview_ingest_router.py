"""POST /api/v1/agent/jobs/{job_id}/preview-ingest — mid-scan preview ingest."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src.main import app
from src.runner.jobs import create_job, update_job_status
from src.runner.registry import approve_runner, register_runner
from src.runner.storage import generate_registration_token


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def approved_runner():
    raw_reg, _ = generate_registration_token()
    runner, raw_auth, err = register_runner(raw_token=raw_reg, name="prev-runner", os_name="linux", arch="x86_64")
    assert err is None
    approve_runner(runner["id"])
    return {"id": runner["id"], "token": raw_auth}


def _job(runner_id, job_type):
    job = create_job(job_type=job_type, org="acme", run_id=f"run-{job_type}", env_vars={"REPO_ID": "asset-1"})
    update_job_status(job["id"], "running", runnerId=runner_id)
    return job


def test_preview_ingest_requires_runner_auth(client):
    resp = client.post("/api/v1/agent/jobs/whatever/preview-ingest")
    assert resp.status_code == 401


def test_preview_ingest_dispatches_and_emits_for_code_scanning(client, approved_runner):
    job = _job(approved_runner["id"], "code_scanning")
    with patch("src.runner.router._dispatch_ingest") as ingest, \
         patch("src.runner.router.get_event_bus") as bus:
        resp = client.post(
            f"/api/v1/agent/jobs/{job['id']}/preview-ingest",
            headers={"Authorization": f"Bearer {approved_runner['token']}"},
        )
    assert resp.status_code == 200 and resp.json()["ok"] is True
    ingest.assert_called_once()
    # A findings.updated event is published so open clients refetch.
    assert bus.return_value.publish_sync.called


def test_preview_ingest_skips_non_verifying_scanner(client, approved_runner):
    job = _job(approved_runner["id"], "secret_scanning")
    with patch("src.runner.router._dispatch_ingest") as ingest:
        resp = client.post(
            f"/api/v1/agent/jobs/{job['id']}/preview-ingest",
            headers={"Authorization": f"Bearer {approved_runner['token']}"},
        )
    assert resp.status_code == 200 and resp.json().get("skipped") == "not_a_verifying_scanner"
    ingest.assert_not_called()
