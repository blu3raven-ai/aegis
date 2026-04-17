"""Admin-facing API endpoints for runner management."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.runner.registry import (
    approve_runner,
    compute_runner_status,
    create_registration_token,
    list_runners_with_status,
    remove_runner,
    revoke_runner,
    rotate_auth_token,
)
from src.runner.storage import list_heartbeats, list_jobs_for_runner, read_runner, update_runner_settings
from src.settings.router import require_permission
from src.shared.config import get_runner_mode, read_app_config, write_app_config

admin_router = APIRouter(prefix="/settings/runners", tags=["runner-admin"])


class RunnerModeRequest(BaseModel):
    mode: str


class RunnerSettingsRequest(BaseModel):
    maxConcurrent: int | None = None
    name: str | None = None


@admin_router.get("")
def list_all_runners(request: Request) -> JSONResponse:
    require_permission(request, "manage_settings")
    runners = list_runners_with_status()
    mode = get_runner_mode()
    return JSONResponse({
        "mode": mode,
        "runners": [
            {
                "id": r["id"],
                "name": r.get("name", ""),
                "status": r["computedStatus"],
                "os": r.get("os", ""),
                "arch": r.get("arch", ""),
                "registeredAt": r.get("registeredAt", ""),
                "approvedAt": r.get("approvedAt"),
                "lastHeartbeatAt": r.get("lastHeartbeatAt", ""),
                "jobsCompleted": r.get("jobsCompleted", 0),
                "maxConcurrent": r.get("maxConcurrent", 2),
                "cpuPercent": r.get("cpuPercent"),
                "cores": r.get("cores"),
                "healthPercent": r.get("healthPercent"),
                "scannerImages": r.get("scannerImages"),
            }
            for r in runners
            if r["computedStatus"] != "archived"
        ],
    })


@admin_router.post("/tokens")
def generate_token(request: Request) -> JSONResponse:
    require_permission(request, "manage_settings")
    raw_token, record = create_registration_token()
    return JSONResponse({
        "token": raw_token,
        "expiresAt": record["expiresAt"],
    })


@admin_router.post("/mode")
def set_runner_mode(request: Request, body: RunnerModeRequest) -> JSONResponse:
    require_permission(request, "manage_settings")
    if body.mode not in ("local", "remote"):
        return JSONResponse({"error": "Invalid mode"}, status_code=400)
    # License: remote mode requires Pro+ (community has max_remote_runners=0)
    if body.mode == "remote":
        from src.license.limits import check_limit
        check_limit(request, "max_remote_runners", 0)

    config = read_app_config()
    config.setdefault("runners", {})["mode"] = body.mode
    write_app_config(config, "settings.runners.mode.updated")
    return JSONResponse({"ok": True, "mode": body.mode})


@admin_router.get("/{runner_id}")
def get_runner_detail(runner_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_settings")
    runner = read_runner(runner_id)
    if not runner:
        return JSONResponse({"error": "Runner not found"}, status_code=404)

    runner["computedStatus"] = compute_runner_status(runner)
    recent_jobs = list_jobs_for_runner(runner_id, limit=10)

    return JSONResponse({
        "runner": {
            "id": runner["id"],
            "name": runner.get("name", ""),
            "status": runner["computedStatus"],
            "os": runner.get("os", ""),
            "arch": runner.get("arch", ""),
            "registeredAt": runner.get("registeredAt", ""),
            "approvedAt": runner.get("approvedAt"),
            "lastHeartbeatAt": runner.get("lastHeartbeatAt", ""),
            "maxConcurrent": runner.get("maxConcurrent", 2),
            "cpuPercent": runner.get("cpuPercent"),
            "memoryUsedGb": runner.get("memoryUsedGb"),
            "memoryTotalGb": runner.get("memoryTotalGb"),
            "diskUsedGb": runner.get("diskUsedGb"),
            "diskTotalGb": runner.get("diskTotalGb"),
            "cores": runner.get("cores"),
            "activeContainers": runner.get("activeContainers") or [],
            "scannerImages": runner.get("scannerImages"),
        },
        "recentJobs": recent_jobs,
    })


@admin_router.get("/{runner_id}/heartbeats")
def get_heartbeat_history(runner_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_settings")
    heartbeats = list_heartbeats(runner_id, since_minutes=60)
    return JSONResponse({"heartbeats": heartbeats})


@admin_router.patch("/{runner_id}/settings")
def patch_runner_settings(runner_id: str, body: RunnerSettingsRequest, request: Request) -> JSONResponse:
    require_permission(request, "manage_settings")
    settings = body.model_dump(exclude_none=True)
    if not settings:
        return JSONResponse({"error": "No settings provided"}, status_code=400)
    updated = update_runner_settings(runner_id, settings)
    if not updated:
        return JSONResponse({"error": "Runner not found"}, status_code=404)
    return JSONResponse({"ok": True, "runner": updated})


@admin_router.post("/{runner_id}/approve")
def approve(runner_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_settings")
    # License: enforce remote runner limit
    from src.license.limits import check_limit
    all_runners = list_runners_with_status()
    approved_count = sum(1 for r in all_runners if r.get("status") == "approved")
    check_limit(request, "max_remote_runners", approved_count)
    runner = approve_runner(runner_id)
    if not runner:
        return JSONResponse({"error": "Runner not found"}, status_code=404)
    return JSONResponse({"ok": True, "status": runner["status"]})


@admin_router.post("/{runner_id}/revoke")
def revoke(runner_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_settings")
    runner = revoke_runner(runner_id)
    if not runner:
        return JSONResponse({"error": "Runner not found"}, status_code=404)
    return JSONResponse({"ok": True})


@admin_router.delete("/{runner_id}")
def delete(runner_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_settings")
    if not remove_runner(runner_id):
        return JSONResponse({"error": "Runner not found"}, status_code=404)
    return JSONResponse({"ok": True})


@admin_router.post("/{runner_id}/rotate-token")
def rotate_token(runner_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_settings")
    new_token, error = rotate_auth_token(runner_id)
    if error:
        return JSONResponse({"error": error}, status_code=404)
    return JSONResponse({"ok": True, "newToken": new_token})
