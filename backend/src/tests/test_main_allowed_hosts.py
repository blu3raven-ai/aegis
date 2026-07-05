"""ALLOWED_HOSTS must be required and parsed, with a loud failure when unset.

A silent dev-defaulted host list in production yields opaque 400s when real
traffic arrives; the production process should refuse to register the
TrustedHostMiddleware in that state.
"""
from __future__ import annotations

import pytest

from src.shared.config import get_allowed_hosts


def test_get_allowed_hosts_raises_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALLOWED_HOSTS", raising=False)
    with pytest.raises(RuntimeError, match="ALLOWED_HOSTS environment variable is required"):
        get_allowed_hosts()


@pytest.mark.parametrize("value", ["", "   ", ",", " , , "])
def test_get_allowed_hosts_raises_when_empty_or_whitespace(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("ALLOWED_HOSTS", value)
    with pytest.raises(RuntimeError, match="ALLOWED_HOSTS"):
        get_allowed_hosts()


def test_get_allowed_hosts_parses_comma_separated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALLOWED_HOSTS", "aegis.example.com, api.aegis.example.com ,*.internal")
    assert get_allowed_hosts() == [
        "aegis.example.com",
        "api.aegis.example.com",
        "*.internal",
    ]


def test_get_allowed_hosts_drops_empty_segments(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALLOWED_HOSTS", "localhost,,127.0.0.1,, testserver ")
    assert get_allowed_hosts() == ["localhost", "127.0.0.1", "testserver"]
