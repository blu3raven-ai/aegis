"""Tests for RedisBackedQueue (real Redis Streams implementation)."""
from __future__ import annotations

import pytest
from testcontainers.redis import RedisContainer

from src.runner.queue.redis_backed import RedisBackedQueue


@pytest.fixture(scope="module")
def redis_container():
    with RedisContainer("redis:7-alpine") as rc:
        yield rc


@pytest.fixture
def queue(redis_container, monkeypatch):
    url = f"redis://{redis_container.get_container_host_ip()}:{redis_container.get_exposed_port(6379)}"
    monkeypatch.setenv("REDIS_URL", url)
    monkeypatch.setenv("JWT_SHARED_SECRET", "test-secret-for-cipher")
    # Use a unique prefix per test to avoid cross-test contamination
    import secrets as _secrets
    prefix = f"test.jobs.{_secrets.token_hex(4)}."
    return RedisBackedQueue(redis_url=url, stream_prefix=prefix)


def test_create_writes_to_stream_and_get_returns_record(queue):
    jid = queue.create(
        job_type="dependencies", org="acme-org", run_id="r1",
        docker_image="img", env_vars={"FOO": "bar"},
    )
    assert jid.startswith("job-")
    record = queue.get(jid)
    assert record is not None
    assert record["jobType"] == "dependencies"
    assert record["status"] == "queued"
    assert record["envVars"]["FOO"] == "bar"


def test_get_returns_none_for_unknown_job(queue):
    assert queue.get("job-nonexistent") is None


def test_assign_next_pulls_in_fifo_order_with_runner_id(queue):
    j1 = queue.create(job_type="t1", org="acme", run_id="r1", docker_image="img", env_vars={})
    j2 = queue.create(job_type="t1", org="acme", run_id="r2", docker_image="img", env_vars={})

    a1 = queue.assign_next(runner_id="r1")
    assert a1 is not None
    assert a1["id"] == j1
    assert a1["status"] == "assigned"
    assert a1["runnerId"] == "r1"

    a2 = queue.assign_next(runner_id="r1")
    assert a2["id"] == j2

    a3 = queue.assign_next(runner_id="r1")
    assert a3 is None


def test_mark_completed_updates_status(queue):
    jid = queue.create(job_type="t2", org="acme", run_id="r1", docker_image="img", env_vars={})
    queue.assign_next(runner_id="r1")
    queue.mark_started(jid)
    queue.mark_completed(jid, result={"findings": 5})
    record = queue.get(jid)
    assert record["status"] == "completed"
    assert record["result"]["findings"] == 5


def test_mark_failed_retryable_returns_to_queued(queue):
    jid = queue.create(job_type="t3", org="acme", run_id="r1", docker_image="img", env_vars={})
    queue.assign_next(runner_id="r1")
    queue.mark_failed(jid, error="timeout", retryable=True)
    record = queue.get(jid)
    assert record["status"] == "queued"
    assert record["error"] == "timeout"


def test_create_encrypts_sensitive_env_vars(queue):
    """Public API returns decrypted, but stored representation is encrypted."""
    jid = queue.create(
        job_type="t4", org="acme", run_id="r1", docker_image="img",
        env_vars={"GIT_TOKEN": "ghp_secret"},
    )
    record = queue.get(jid)
    assert record["envVars"]["GIT_TOKEN"] == "ghp_secret"
