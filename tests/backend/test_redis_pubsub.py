"""Tests for the queued-job pub/sub notification channel."""
from __future__ import annotations

import json
import threading
import time

import pytest
from testcontainers.redis import RedisContainer

from src.runner.queue.redis_pubsub import JobQueuedPubSub


@pytest.fixture(scope="module")
def redis_container():
    with RedisContainer("redis:7-alpine") as rc:
        yield rc


@pytest.fixture
def pubsub(redis_container):
    url = f"redis://{redis_container.get_container_host_ip()}:{redis_container.get_exposed_port(6379)}"
    return JobQueuedPubSub(redis_url=url)


def test_publish_then_subscribe_receives(pubsub):
    received = []

    def listen():
        for msg in pubsub.subscribe("dependencies", timeout=2.0):
            received.append(msg)
            break

    t = threading.Thread(target=listen, daemon=True)
    t.start()
    time.sleep(0.2)
    pubsub.publish("dependencies", job_id="job-abc")
    t.join(timeout=3.0)
    assert received == [{"scanner_type": "dependencies", "job_id": "job-abc"}]


def test_subscribe_times_out_with_no_messages(pubsub):
    received = []
    for msg in pubsub.subscribe("dependencies", timeout=0.3):
        received.append(msg)
    assert received == []


def test_publish_to_different_channels_isolated(pubsub):
    """Publish to 'dependencies' shouldn't reach a 'secrets' subscriber."""
    received = []

    def listen():
        for msg in pubsub.subscribe("secrets", timeout=0.5):
            received.append(msg)

    t = threading.Thread(target=listen, daemon=True)
    t.start()
    time.sleep(0.2)
    pubsub.publish("dependencies", job_id="job-x")
    t.join(timeout=1.0)
    assert received == []


def test_queue_create_publishes_queued_notification(redis_container, monkeypatch):
    """End-to-end: creating a job via any queue triggers a pub/sub notification."""
    url = f"redis://{redis_container.get_container_host_ip()}:{redis_container.get_exposed_port(6379)}"
    monkeypatch.setenv("REDIS_URL", url)
    monkeypatch.setenv("JWT_SHARED_SECRET", "test-secret-for-cipher")

    pubsub = JobQueuedPubSub(redis_url=url)

    from src.runner.queue.redis_backed import RedisBackedQueue
    queue = RedisBackedQueue(redis_url=url, stream_prefix="pubsub-test.")

    received = []

    def listen():
        for msg in pubsub.subscribe("dependencies", timeout=2.0):
            received.append(msg)
            break

    t = threading.Thread(target=listen, daemon=True)
    t.start()
    time.sleep(0.2)

    job_id = queue.create(
        job_type="dependencies", org="acme-org", run_id="r1",
        docker_image="img", env_vars={},
    )

    t.join(timeout=3.0)
    assert len(received) == 1
    assert received[0]["job_id"] == job_id
    assert received[0]["scanner_type"] == "dependencies"
