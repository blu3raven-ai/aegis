"""Contract tests for the in-memory TTL cache.

Covers hit/miss, TTL expiry (via a controllable clock), and the prefix-based
invalidate semantics — invalidate(key) drops every entry whose key *starts with*
the argument, which is the intended group-invalidation behaviour (and an easy
gotcha if a prefix is also a prefix of an unrelated key).
"""
from __future__ import annotations

import pytest

from src.shared import ttl_cache as ttl_cache_mod
from src.shared.ttl_cache import TtlCache


class _Clock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def time(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch):
    c = _Clock()
    monkeypatch.setattr(ttl_cache_mod, "time", c)  # module does `time.time()`
    return c


def test_miss_returns_none(clock):
    assert TtlCache().get("absent") is None


def test_set_then_get_within_ttl(clock):
    cache = TtlCache(ttl_seconds=300)
    cache.set("k", {"v": 1})
    assert cache.get("k") == {"v": 1}
    clock.now += 299  # still inside the window
    assert cache.get("k") == {"v": 1}


def test_entry_expires_after_ttl(clock):
    cache = TtlCache(ttl_seconds=300)
    cache.set("k", "v")
    clock.now += 300  # boundary: 300 is NOT < 300
    assert cache.get("k") is None
    cache.set("k", "v")
    clock.now += 301
    assert cache.get("k") is None


def test_invalidate_is_prefix_scoped(clock):
    cache = TtlCache()
    cache.set("user:1", "a")
    cache.set("user:2", "b")
    cache.set("post:1", "c")

    cache.invalidate("user")

    assert cache.get("user:1") is None
    assert cache.get("user:2") is None
    assert cache.get("post:1") == "c"  # unrelated prefix untouched


def test_invalidate_prefix_also_drops_longer_keys(clock):
    # Documents the gotcha: invalidate("user:1") is a prefix match, so it also
    # drops "user:10".
    cache = TtlCache()
    cache.set("user:1", "a")
    cache.set("user:10", "b")
    cache.invalidate("user:1")
    assert cache.get("user:1") is None
    assert cache.get("user:10") is None


def test_invalidate_all_clears_everything(clock):
    cache = TtlCache()
    cache.set("a", 1)
    cache.set("b", 2)
    cache.invalidate()  # no key -> clear all
    assert cache.get("a") is None
    assert cache.get("b") is None
