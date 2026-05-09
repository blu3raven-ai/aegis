"""Tests for the shared TTL cache."""
import time
from src.shared.ttl_cache import TtlCache


def test_get_returns_none_for_missing_key():
    cache = TtlCache(ttl_seconds=60)
    assert cache.get("missing") is None


def test_set_and_get_returns_value():
    cache = TtlCache(ttl_seconds=60)
    cache.set("key1", {"data": 42})
    assert cache.get("key1") == {"data": 42}


def test_expired_entry_returns_none():
    cache = TtlCache(ttl_seconds=0)  # 0 second TTL = instant expiry
    cache.set("key1", "value")
    time.sleep(0.01)
    assert cache.get("key1") is None


def test_invalidate_specific_key():
    cache = TtlCache(ttl_seconds=60)
    cache.set("cache:org1", "v1")
    cache.set("cache:org2", "v2")
    cache.invalidate("cache:org1")
    assert cache.get("cache:org1") is None
    assert cache.get("cache:org2") == "v2"


def test_invalidate_all():
    cache = TtlCache(ttl_seconds=60)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.invalidate()
    assert cache.get("a") is None
    assert cache.get("b") is None


def test_invalidate_prefix_removes_matching_keys():
    cache = TtlCache(ttl_seconds=60)
    cache.set("cache:org1:a", 1)
    cache.set("cache:org1:b", 2)
    cache.set("cache:org2:a", 3)
    cache.invalidate("cache:org1")
    assert cache.get("cache:org1:a") is None
    assert cache.get("cache:org1:b") is None
    assert cache.get("cache:org2:a") == 3
