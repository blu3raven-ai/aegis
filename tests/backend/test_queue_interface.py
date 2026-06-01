"""Tests for the JobQueue Protocol contract.

Every concrete queue backend must satisfy this contract. Phase 0 ships
two implementations: FileBackedQueue (wraps current jobs.py) and
RedisBackedQueue stub.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from src.runner.queue import JobQueue
from src.runner.queue.file_backed import FileBackedQueue


def test_jobqueue_protocol_methods_exist():
    expected = {"create", "assign_next", "mark_started", "mark_completed",
                "mark_failed", "get"}
    actual = {m for m in dir(JobQueue) if not m.startswith("_")}
    missing = expected - actual
    assert not missing, f"JobQueue Protocol missing methods: {missing}"


def test_file_backed_queue_satisfies_protocol():
    with tempfile.TemporaryDirectory() as tmp:
        q: JobQueue = FileBackedQueue(storage_dir=Path(tmp))
        jid = q.create(
            job_type="dependencies",
            org="acme-org",
            run_id="run-1",
            docker_image="aegis/scanner-deps:latest",
            env_vars={"FOO": "bar"},
        )
        record = q.get(jid)
        assert record is not None
        assert record["status"] == "queued"
        assert record["jobType"] == "dependencies"


def test_file_backed_queue_assigns_oldest_first():
    with tempfile.TemporaryDirectory() as tmp:
        q = FileBackedQueue(storage_dir=Path(tmp))
        j1 = q.create(job_type="t", org="acme", run_id="r1", docker_image="img", env_vars={})
        import time; time.sleep(0.01)
        j2 = q.create(job_type="t", org="acme", run_id="r2", docker_image="img", env_vars={})
        assigned = q.assign_next(runner_id="runner-1")
        assert assigned is not None
        assert assigned["id"] == j1
        assert assigned["runnerId"] == "runner-1"
        assigned2 = q.assign_next(runner_id="runner-1")
        assert assigned2["id"] == j2
        assigned3 = q.assign_next(runner_id="runner-1")
        assert assigned3 is None


def test_file_backed_queue_persists_runner_id():
    """Regression: assign_next must write runner_id into the record so that
    downstream code (requeue_stale_jobs, complete_job stats) can read it."""
    with tempfile.TemporaryDirectory() as tmp:
        q = FileBackedQueue(storage_dir=Path(tmp))
        jid = q.create(job_type="t", org="acme", run_id="r1", docker_image="img", env_vars={})
        q.assign_next(runner_id="runner-xyz")
        record = q.get(jid)
        assert record["runnerId"] == "runner-xyz"


def test_factory_returns_file_backed_by_default(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.delenv("JOB_QUEUE_BACKEND", raising=False)
        monkeypatch.setenv("DATA_DIR", tmp)
        from src.runner.queue.factory import get_queue, reset_cache
        reset_cache()
        q = get_queue()
        from src.runner.queue.file_backed import FileBackedQueue
        assert isinstance(q, FileBackedQueue)


def test_factory_returns_redis_backed_when_configured(monkeypatch):
    monkeypatch.setenv("JOB_QUEUE_BACKEND", "redis")
    from src.runner.queue.factory import get_queue, reset_cache
    reset_cache()
    q = get_queue()
    from src.runner.queue.redis_backed import RedisBackedQueue
    assert isinstance(q, RedisBackedQueue)


def test_factory_returns_postgres_backed_when_configured(monkeypatch):
    monkeypatch.setenv("JOB_QUEUE_BACKEND", "postgres")
    from src.runner.queue.factory import get_queue, reset_cache
    reset_cache()
    q = get_queue()
    from src.runner.queue.postgres_backed import PostgresBackedQueue
    assert isinstance(q, PostgresBackedQueue)


def test_factory_raises_on_unknown_backend(monkeypatch):
    monkeypatch.setenv("JOB_QUEUE_BACKEND", "lol-nope")
    from src.runner.queue.factory import get_queue, reset_cache
    reset_cache()
    with pytest.raises(ValueError):
        get_queue()
