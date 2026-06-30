"""Unit coverage for the file-backed runner job queue.

One JSON file per job; sensitive env vars are encrypted at rest and decrypted
on read. Pins the queue lifecycle (create → assign → start → complete/fail),
the at-rest encryption boundary, and FIFO assignment ordering.
"""
from __future__ import annotations

import json
import os

os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

import pytest

from src.runner.queue.file_backed import FileBackedQueue


@pytest.fixture
def queue(tmp_path):
    return FileBackedQueue(storage_dir=tmp_path)


def test_create_writes_queued_record(queue, tmp_path):
    job_id = queue.create(job_type="scan", org="acme-org", run_id="run-1", env_vars={})
    assert job_id.startswith("job-")
    on_disk = json.loads((tmp_path / f"{job_id}.json").read_text())
    assert on_disk["status"] == "queued"
    assert on_disk["org"] == "acme-org"
    assert on_disk["runId"] == "run-1"
    assert on_disk["runnerId"] is None
    assert on_disk["createdAt"]


def test_get_returns_none_for_unknown_job(queue):
    assert queue.get("job-does-not-exist") is None


def test_sensitive_env_encrypted_at_rest_and_decrypted_on_get(queue, tmp_path):
    job_id = queue.create(
        job_type="scan",
        org="acme-org",
        run_id="run-1",
        env_vars={"GIT_TOKEN": "supersecret", "PUBLIC_FLAG": "plain"},
    )
    on_disk = json.loads((tmp_path / f"{job_id}.json").read_text())
    # Sensitive value never lands in cleartext; non-sensitive stays as-is.
    assert on_disk["envVars"]["GIT_TOKEN"].startswith("ENC:")
    assert "supersecret" not in on_disk["envVars"]["GIT_TOKEN"]
    assert on_disk["envVars"]["PUBLIC_FLAG"] == "plain"
    # get() round-trips back to plaintext.
    record = queue.get(job_id)
    assert record["envVars"]["GIT_TOKEN"] == "supersecret"
    assert record["envVars"]["PUBLIC_FLAG"] == "plain"


def test_assign_next_claims_queued_job_and_decrypts(queue):
    job_id = queue.create(
        job_type="scan", org="acme-org", run_id="run-1",
        env_vars={"GIT_TOKEN": "tok"},
    )
    claimed = queue.assign_next("runner-A")
    assert claimed is not None
    assert claimed["id"] == job_id
    assert claimed["status"] == "assigned"
    assert claimed["runnerId"] == "runner-A"
    assert claimed["startedAt"]
    # Returned env is decrypted for the runner to consume.
    assert claimed["envVars"]["GIT_TOKEN"] == "tok"


def test_assign_next_returns_none_when_nothing_queued(queue):
    queue.create(job_type="scan", org="acme-org", run_id="run-1", env_vars={})
    queue.assign_next("runner-A")  # drains the only job
    assert queue.assign_next("runner-A") is None


def test_assign_next_is_fifo_by_created_at(queue, tmp_path):
    older = queue.create(job_type="scan", org="o", run_id="r-old", env_vars={})
    newer = queue.create(job_type="scan", org="o", run_id="r-new", env_vars={})
    # Force a deterministic ordering regardless of millisecond collisions.
    for job_id, created in ((older, "2026-01-01T00:00:00.000Z"), (newer, "2026-01-02T00:00:00.000Z")):
        p = tmp_path / f"{job_id}.json"
        rec = json.loads(p.read_text())
        rec["createdAt"] = created
        p.write_text(json.dumps(rec))
    assert queue.assign_next("runner-A")["id"] == older
    assert queue.assign_next("runner-B")["id"] == newer


def test_mark_started_then_completed(queue):
    job_id = queue.create(job_type="scan", org="o", run_id="r", env_vars={})
    queue.assign_next("runner-A")
    queue.mark_started(job_id)
    assert queue.get(job_id)["status"] == "running"
    queue.mark_completed(job_id, result={"findings": 3})
    done = queue.get(job_id)
    assert done["status"] == "completed"
    assert done["completedAt"]
    assert done["result"] == {"findings": 3}


def test_mark_failed_non_retryable_is_terminal(queue):
    job_id = queue.create(job_type="scan", org="o", run_id="r", env_vars={})
    queue.mark_failed(job_id, "boom")
    rec = queue.get(job_id)
    assert rec["status"] == "failed"
    assert rec["error"] == "boom"


def test_mark_failed_retryable_requeues(queue):
    job_id = queue.create(job_type="scan", org="o", run_id="r", env_vars={})
    queue.assign_next("runner-A")
    queue.mark_failed(job_id, "transient", retryable=True)
    rec = queue.get(job_id)
    # Retryable failure goes back to queued so another runner can claim it.
    assert rec["status"] == "queued"
    assert rec["error"] == "transient"
    assert queue.assign_next("runner-B")["id"] == job_id
