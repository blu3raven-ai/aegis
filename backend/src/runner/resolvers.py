"""GraphQL resolvers for runner management (admin-facing, read-only).

All write operations live on REST under ``/api/v1/runners`` —
see ``src.runner.admin_service`` and ``src.runner.admin_router``.
"""
from __future__ import annotations

from typing import Optional

import strawberry
from graphql import GraphQLError

from src.authz.enforcement import has_permission
from src.authz.permissions.catalog import MANAGE_RUNNERS
from src.runner.registry import (
    compute_runner_status,
    list_runners_with_status,
)
from src.runner.storage import (
    list_heartbeats,
    list_jobs_for_runner,
    read_runner,
)
from src.shared.config import get_runner_mode


def _require_manage_runners(ctx: dict) -> None:
    """Gate runner reads on manage_runners. Backwards-compatible with
    pre-split deployments because manage_settings IMPLIES manage_runners
    (see src.authz.permissions.service.IMPLIED)."""
    if not has_permission(ctx["request"], MANAGE_RUNNERS):
        raise GraphQLError(
            f"Permission denied: {MANAGE_RUNNERS}",
            extensions={"code": "PERMISSION_DENIED"},
        )


@strawberry.type
class RunnerGQL:
    id: str
    name: str
    status: str
    os: str
    arch: str
    registered_at: str
    approved_at: Optional[str]
    last_heartbeat_at: str
    jobs_completed: int
    max_concurrent: int
    cpu_percent: Optional[float]
    cores: Optional[int]
    health_percent: Optional[int]


@strawberry.type
class RunnerDetailGQL:
    id: str
    name: str
    status: str
    os: str
    arch: str
    registered_at: str
    approved_at: Optional[str]
    last_heartbeat_at: str
    max_concurrent: int
    cpu_percent: Optional[float]
    cores: Optional[int]
    memory_used_gb: Optional[float]
    memory_total_gb: Optional[float]
    disk_used_gb: Optional[float]
    disk_total_gb: Optional[float]


@strawberry.type
class RunnerJobGQL:
    id: str
    job_type: str
    org: str
    run_id: str
    status: str
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]


@strawberry.type
class HeartbeatEntryGQL:
    received_at: str
    cpu_percent: Optional[float]
    memory_used_gb: Optional[float]


@strawberry.type
class RunnersListResult:
    mode: str
    runners: list[RunnerGQL]


@strawberry.type
class RunnerDetailResult:
    runner: RunnerDetailGQL
    recent_jobs: list[RunnerJobGQL]


def _runner_dict_to_gql(r: dict) -> RunnerGQL:
    return RunnerGQL(
        id=r["id"],
        name=r.get("name", ""),
        status=r.get("computedStatus", r.get("status", "")),
        os=r.get("os", ""),
        arch=r.get("arch", ""),
        registered_at=r.get("registeredAt", ""),
        approved_at=r.get("approvedAt"),
        last_heartbeat_at=r.get("lastHeartbeatAt", ""),
        jobs_completed=r.get("jobsCompleted", 0),
        max_concurrent=r.get("maxConcurrent", 2),
        cpu_percent=r.get("cpuPercent"),
        cores=r.get("cores"),
        health_percent=r.get("healthPercent"),
    )


def _runner_dict_to_detail_gql(r: dict) -> RunnerDetailGQL:
    return RunnerDetailGQL(
        id=r["id"],
        name=r.get("name", ""),
        status=r.get("computedStatus", r.get("status", "")),
        os=r.get("os", ""),
        arch=r.get("arch", ""),
        registered_at=r.get("registeredAt", ""),
        approved_at=r.get("approvedAt"),
        last_heartbeat_at=r.get("lastHeartbeatAt", ""),
        max_concurrent=r.get("maxConcurrent", 2),
        cpu_percent=r.get("cpuPercent"),
        cores=r.get("cores"),
        memory_used_gb=r.get("memoryUsedGb"),
        memory_total_gb=r.get("memoryTotalGb"),
        disk_used_gb=r.get("diskUsedGb"),
        disk_total_gb=r.get("diskTotalGb"),
    )


def _job_dict_to_gql(j: dict) -> RunnerJobGQL:
    return RunnerJobGQL(
        id=j.get("id", ""),
        job_type=j.get("jobType", j.get("type", "")),
        org=j.get("org", ""),
        run_id=j.get("runId", ""),
        status=j.get("status", ""),
        created_at=j.get("createdAt", ""),
        started_at=j.get("startedAt"),
        completed_at=j.get("completedAt"),
    )


def _hb_dict_to_gql(h: dict) -> HeartbeatEntryGQL:
    return HeartbeatEntryGQL(
        received_at=h.get("receivedAt", ""),
        cpu_percent=h.get("cpuPercent"),
        memory_used_gb=h.get("memoryUsedGb"),
    )


# ── Queries ────────────────────────────────────────────────────────────────────

def runners(*, info_context: dict) -> RunnersListResult:
    _require_manage_runners(info_context)
    all_runners = list_runners_with_status()
    mode = get_runner_mode()
    return RunnersListResult(
        mode=mode,
        runners=[
            _runner_dict_to_gql(r)
            for r in all_runners
            if r.get("computedStatus") != "archived"
        ],
    )


def runner(*, runner_id: str, info_context: dict) -> Optional[RunnerDetailResult]:
    _require_manage_runners(info_context)
    r = read_runner(runner_id)
    if r is None:
        return None
    r["computedStatus"] = compute_runner_status(r)
    recent_jobs = list_jobs_for_runner(runner_id, limit=10)
    return RunnerDetailResult(
        runner=_runner_dict_to_detail_gql(r),
        recent_jobs=[_job_dict_to_gql(j) for j in recent_jobs],
    )


def runner_heartbeats(*, runner_id: str, info_context: dict) -> list[HeartbeatEntryGQL]:
    _require_manage_runners(info_context)
    heartbeats = list_heartbeats(runner_id, since_minutes=60)
    return [_hb_dict_to_gql(h) for h in heartbeats]
