"""Tests for Redis stream config loading."""
from __future__ import annotations

import pytest

from src.shared.config import load_redis_stream_config


def test_redis_stream_config_defaults(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("EVENT_STREAM_PREFIX", raising=False)
    monkeypatch.delenv("EVENT_STREAM_MAX_LEN", raising=False)
    cfg = load_redis_stream_config()
    assert cfg["url"] == "redis://localhost:6379/0"
    assert cfg["stream_prefix"] == "aegis.events."
    assert cfg["max_len"] == 100_000


def test_redis_stream_config_env_override(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://prod:6379/2")
    monkeypatch.setenv("EVENT_STREAM_PREFIX", "test.")
    monkeypatch.setenv("EVENT_STREAM_MAX_LEN", "5000")
    cfg = load_redis_stream_config()
    assert cfg["url"] == "redis://prod:6379/2"
    assert cfg["stream_prefix"] == "test."
    assert cfg["max_len"] == 5000


def test_redis_password_marked_sensitive():
    from src.shared.config import _SENSITIVE_KEYS
    assert "redisPassword" in _SENSITIVE_KEYS
