"""Tests for the simplified scanner prerequisites endpoint.

Post-migration, prerequisites = 'is at least one healthy runner connected?'.
Scanner-image readiness is no longer a concept."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.settings import router as settings_router


def _make_runner(*, last_seen_seconds_ago: int = 5, status: str = "online") -> dict:
    return {
        "id": "runner-1",
        "name": "runner-1",
        "status": status,
        "lastSeen": (datetime.now(timezone.utc) - timedelta(seconds=last_seen_seconds_ago)).isoformat(),
        "computedStatus": status,
    }


def test_prerequisites_ready_when_healthy_runner_exists():
    """A runner heartbeating in the last 60s satisfies prerequisites for every tool."""
    runners = [_make_runner(last_seen_seconds_ago=10, status="online")]
    for tool in ("dependencies", "container", "secrets", "code-scanning"):
        result = settings_router._evaluate_prerequisites_for_tool(tool, runners)
        assert result["status"] == "ready", f"tool={tool} should be ready, got {result}"


def test_prerequisites_no_runner_when_no_recent_heartbeat():
    """No runners → status='no_runner'."""
    result = settings_router._evaluate_prerequisites_for_tool("dependencies", [])
    assert result["status"] == "no_runner"


def test_prerequisites_no_runner_when_all_runners_stale():
    """Runners with stale heartbeats (> threshold) count as no_runner."""
    stale = [_make_runner(last_seen_seconds_ago=600, status="online")]
    result = settings_router._evaluate_prerequisites_for_tool("dependencies", stale)
    assert result["status"] == "no_runner"
