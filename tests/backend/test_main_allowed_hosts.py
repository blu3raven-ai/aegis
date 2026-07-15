"""ALLOWED_HOSTS merges a safe baseline (loopback + internal service name) with
any operator-supplied public hostnames.

The baseline is always trusted so service-to-service traffic (the runner reaching
the backend at its internal hostname) works with zero config; ALLOWED_HOSTS is
purely additive for public domains.
"""
from __future__ import annotations

import pytest

from src.shared.config import _BASELINE_HOSTS, get_allowed_hosts


def test_get_allowed_hosts_returns_baseline_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALLOWED_HOSTS", raising=False)
    assert get_allowed_hosts() == list(_BASELINE_HOSTS)


@pytest.mark.parametrize("value", ["", "   ", ",", " , , "])
def test_get_allowed_hosts_returns_baseline_when_empty_or_whitespace(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("ALLOWED_HOSTS", value)
    assert get_allowed_hosts() == list(_BASELINE_HOSTS)


def test_get_allowed_hosts_merges_public_hosts_onto_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ALLOWED_HOSTS", "scan.example.com, api.example.com ")
    assert get_allowed_hosts() == [
        *_BASELINE_HOSTS,
        "scan.example.com",
        "api.example.com",
    ]


def test_get_allowed_hosts_dedups_and_drops_empty_segments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Baseline entries repeated in the env var collapse; empty segments drop.
    monkeypatch.setenv("ALLOWED_HOSTS", "localhost,,scan.example.com,, aegis ")
    assert get_allowed_hosts() == [*_BASELINE_HOSTS, "scan.example.com"]
