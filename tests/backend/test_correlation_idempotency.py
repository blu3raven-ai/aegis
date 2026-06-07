"""Tests for the Postgres-backed correlation idempotency helper."""
from __future__ import annotations

import threading
import time

import pytest

from src.correlation import idempotency


@pytest.fixture(autouse=True)
def _clear_table():
    idempotency._delete_all_for_test()
    yield
    idempotency._delete_all_for_test()


def test_check_and_set_first_call_returns_true():
    assert idempotency.check_and_set("k1", "v", ttl_seconds=60) is True


def test_check_and_set_duplicate_returns_false():
    assert idempotency.check_and_set("k1", "v", ttl_seconds=60) is True
    assert idempotency.check_and_set("k1", "v", ttl_seconds=60) is False


def test_check_and_set_after_expiry_returns_true():
    assert idempotency.check_and_set("k1", "v", ttl_seconds=1) is True
    time.sleep(1.2)
    assert idempotency.check_and_set("k1", "v", ttl_seconds=60) is True


def test_check_and_set_is_atomic_under_concurrency():
    """50 threads race on the same key — exactly one wins."""
    results: list[bool] = []
    results_lock = threading.Lock()

    def _attempt():
        ok = idempotency.check_and_set("race-key", "v", ttl_seconds=60)
        with results_lock:
            results.append(ok)

    threads = [threading.Thread(target=_attempt) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(True) == 1
    assert results.count(False) == 49


def test_delete_expired_removes_only_expired_rows():
    idempotency.check_and_set("expired-1", "v", ttl_seconds=1)
    idempotency.check_and_set("expired-2", "v", ttl_seconds=1)
    idempotency.check_and_set("fresh-1", "v", ttl_seconds=60)
    time.sleep(1.2)

    deleted = idempotency.delete_expired()
    assert deleted == 2
    assert idempotency.check_and_set("fresh-1", "v", ttl_seconds=60) is False
