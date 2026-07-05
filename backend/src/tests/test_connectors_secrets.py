from __future__ import annotations

import pytest

from src.connectors.secrets import (
    EnvSecretResolver,
    MissingSecretError,
    SecretResolver,
)


def test_env_resolver_returns_value(monkeypatch):
    monkeypatch.setenv("MY_SECRET", "hunter2")
    resolver = EnvSecretResolver()
    assert resolver.resolve("MY_SECRET") == "hunter2"


def test_env_resolver_missing_raises(monkeypatch):
    monkeypatch.delenv("ABSENT_SECRET", raising=False)
    resolver = EnvSecretResolver()
    with pytest.raises(MissingSecretError, match="ABSENT_SECRET"):
        resolver.resolve("ABSENT_SECRET")


def test_env_resolver_empty_value_raises(monkeypatch):
    """An empty env var is treated as missing — an explicit deployment error,
    never a silent bypass."""
    monkeypatch.setenv("EMPTY_SECRET", "")
    resolver = EnvSecretResolver()
    with pytest.raises(MissingSecretError):
        resolver.resolve("EMPTY_SECRET")


def test_env_resolver_satisfies_protocol():
    """EnvSecretResolver must satisfy the SecretResolver Protocol."""
    resolver: SecretResolver = EnvSecretResolver()
    assert hasattr(resolver, "resolve")
