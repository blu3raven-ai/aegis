"""Simple in-memory TTL cache for API responses.

Usage:
    cache = TtlCache(ttl_seconds=300)
    cached = cache.get("key")
    if cached is not None:
        return cached
    result = expensive_computation()
    cache.set("key", result)
    return result

    # Invalidate on data change:
    cache.invalidate("key")  # or cache.invalidate() to clear all
"""
from __future__ import annotations

import time
from typing import Any


class TtlCache:
    def __init__(self, ttl_seconds: int = 300):
        self._store: dict[str, tuple[float, Any]] = {}
        self._ttl = ttl_seconds

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry and (time.time() - entry[0]) < self._ttl:
            return entry[1]
        return None

    def set(self, key: str, value: Any) -> None:
        self._store[key] = (time.time(), value)

    def invalidate(self, key: str | None = None) -> None:
        if key:
            keys_to_drop = [k for k in self._store if k.startswith(key)]
            for k in keys_to_drop:
                self._store.pop(k, None)
        else:
            self._store.clear()
