"""Unit tests for runners GQL resolvers (read-only)."""
from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from graphql import GraphQLError

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.runner.resolvers import (  # noqa: E402
    runner,
    runner_heartbeats,
    runners,
)

_NOW = "2025-01-01T00:00:00+00:00"

_RUNNER_RECORD = {
    "id": "runner-abc123",
    "name": "test-runner",
    "status": "approved",
    "os": "linux",
    "arch": "amd64",
    "registeredAt": _NOW,
    "approvedAt": _NOW,
    "lastHeartbeatAt": _NOW,
    "jobsCompleted": 5,
    "maxConcurrent": 2,
    "cpuPercent": 12.5,
    "cores": 4,
    "healthPercent": 90,
    "memoryUsedGb": 2.0,
    "memoryTotalGb": 8.0,
    "diskUsedGb": 10.0,
    "diskTotalGb": 100.0,
    "computedStatus": "online",
}

_JOB_RECORD = {
    "id": "job-1",
    "jobType": "dependencies_scanning",
    "org": "acme-org",
    "runId": "run-1",
    "status": "completed",
    "createdAt": _NOW,
    "startedAt": _NOW,
    "completedAt": _NOW,
}

_HB_RECORD = {
    "receivedAt": _NOW,
    "cpuPercent": 12.5,
    "memoryUsedGb": 2.0,
}


def _ctx_allow() -> dict:
    return {"request": SimpleNamespace(_allow=True)}


def _ctx_deny() -> dict:
    return {"request": SimpleNamespace(_allow=False)}


# ── Permission enforcement ──────────────────────────────────────────────────

@patch("src.runner.resolvers.has_permission", return_value=False)
def test_runners_query_requires_permission(mock_perm):
    with pytest.raises(GraphQLError) as exc_info:
        runners(info_context=_ctx_deny())
    assert exc_info.value.extensions["code"] == "PERMISSION_DENIED"


@patch("src.runner.resolvers.has_permission", return_value=False)
def test_runner_query_requires_permission(mock_perm):
    with pytest.raises(GraphQLError) as exc_info:
        runner(runner_id="runner-abc123", info_context=_ctx_deny())
    assert exc_info.value.extensions["code"] == "PERMISSION_DENIED"


@patch("src.runner.resolvers.has_permission", return_value=False)
def test_runner_heartbeats_requires_permission(mock_perm):
    with pytest.raises(GraphQLError) as exc_info:
        runner_heartbeats(runner_id="runner-abc123", info_context=_ctx_deny())
    assert exc_info.value.extensions["code"] == "PERMISSION_DENIED"


# ── runners() query ─────────────────────────────────────────────────────────

@patch("src.runner.resolvers.has_permission", return_value=True)
@patch("src.runner.resolvers.list_runners_with_status", return_value=[_RUNNER_RECORD])
def test_runners_returns_list(mock_list, mock_perm):
    result = runners(info_context=_ctx_allow())
    assert len(result.runners) == 1
    r = result.runners[0]
    assert r.id == "runner-abc123"
    assert r.status == "online"
    assert r.max_concurrent == 2


@patch("src.runner.resolvers.has_permission", return_value=True)
@patch("src.runner.resolvers.list_runners_with_status", return_value=[
    {**_RUNNER_RECORD, "computedStatus": "archived"},
])
def test_runners_excludes_archived(mock_list, mock_perm):
    result = runners(info_context=_ctx_allow())
    assert result.runners == []


# ── runner() query ──────────────────────────────────────────────────────────

@patch("src.runner.resolvers.has_permission", return_value=True)
@patch("src.runner.resolvers.list_jobs_for_runner", return_value=[_JOB_RECORD])
@patch("src.runner.resolvers.compute_runner_status", return_value="online")
@patch("src.runner.resolvers.read_runner", return_value=_RUNNER_RECORD)
def test_runner_returns_detail(mock_read, mock_status, mock_jobs, mock_perm):
    result = runner(runner_id="runner-abc123", info_context=_ctx_allow())
    assert result is not None
    assert result.runner.id == "runner-abc123"
    assert result.runner.memory_total_gb == 8.0
    assert len(result.recent_jobs) == 1
    assert result.recent_jobs[0].job_type == "dependencies_scanning"


@patch("src.runner.resolvers.has_permission", return_value=True)
@patch("src.runner.resolvers.read_runner", return_value=None)
def test_runner_returns_none_when_not_found(mock_read, mock_perm):
    result = runner(runner_id="nonexistent", info_context=_ctx_allow())
    assert result is None


# ── runner_heartbeats() query ───────────────────────────────────────────────

@patch("src.runner.resolvers.has_permission", return_value=True)
@patch("src.runner.resolvers.list_heartbeats", return_value=[_HB_RECORD])
def test_runner_heartbeats_returns_list(mock_hb, mock_perm):
    result = runner_heartbeats(runner_id="runner-abc123", info_context=_ctx_allow())
    assert len(result) == 1
    assert result[0].cpu_percent == 12.5
    assert result[0].memory_used_gb == 2.0
