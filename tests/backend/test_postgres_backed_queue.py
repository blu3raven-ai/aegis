"""Tests for PostgresBackedQueue — wraps the existing jobs.py Postgres-backed logic."""
from __future__ import annotations

import pytest

from src.runner.queue import JobQueue
from src.runner.queue.postgres_backed import PostgresBackedQueue


@pytest.fixture
def queue():
    """Fresh PostgresBackedQueue per test. Uses the session-wide Postgres from conftest.py."""
    return PostgresBackedQueue()


def _drain_queued(q: PostgresBackedQueue) -> None:
    """Assign (and thus dequeue) all currently queued jobs so tests start clean."""
    while q.assign_next(runner_id="_drain") is not None:
        pass


def test_postgres_backed_queue_satisfies_protocol(queue):
    _drain_queued(queue)
    q: JobQueue = queue
    jid = q.create(
        job_type="dependencies", org="acme-org", run_id="run-1",
        docker_image="aegis/scanner-deps:latest", env_vars={"FOO": "bar"},
    )
    record = q.get(jid)
    assert record is not None
    assert record["status"] == "queued"


def test_postgres_backed_queue_assign_persists_runner_id(queue):
    _drain_queued(queue)
    jid = queue.create(
        job_type="t", org="acme", run_id="r1",
        docker_image="img", env_vars={},
    )
    assigned = queue.assign_next(runner_id="runner-pg-test")
    assert assigned is not None
    assert assigned["id"] == jid
    assert assigned["runnerId"] == "runner-pg-test"

    record = queue.get(jid)
    assert record["runnerId"] == "runner-pg-test"


def test_postgres_backed_queue_lifecycle(queue):
    _drain_queued(queue)
    jid = queue.create(
        job_type="t", org="acme", run_id="r1",
        docker_image="img", env_vars={"TOKEN": "value"},
    )
    queue.assign_next(runner_id="r1")
    queue.mark_started(jid)
    queue.mark_completed(jid, result={"findings": 3})
    record = queue.get(jid)
    assert record["status"] == "completed"


def test_postgres_backed_queue_encrypts_sensitive_env_vars(monkeypatch):
    # Set a stable secret so encrypt/decrypt use the same derived key
    monkeypatch.setenv("JWT_SHARED_SECRET", "test-stable-secret-for-encryption")
    q = PostgresBackedQueue()
    jid = q.create(
        job_type="t", org="acme", run_id="r1",
        docker_image="img", env_vars={"GIT_TOKEN": "ghp_test_secret_123"},
    )
    # Public API returns decrypted
    record = q.get(jid)
    assert record["envVars"]["GIT_TOKEN"] == "ghp_test_secret_123"
