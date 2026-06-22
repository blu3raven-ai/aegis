"""Runner admin write operations."""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from src.license.limits import check_limit
from src.runner.registry import (
    approve_runner as _approve_runner,
    compute_runner_status,
    create_registration_token,
    list_runners_with_status,
    remove_runner as _remove_runner,
    revoke_runner as _revoke_runner,
    rotate_auth_token,
)
from src.runner.storage import update_runner_settings as _update_runner_settings
from src.shared.config import read_app_config, write_app_config


def _runner_to_dict(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": r.get("id", ""),
        "name": r.get("name", ""),
        "status": r.get("computedStatus", r.get("status", "")),
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
    }


def generate_token() -> dict[str, Any]:
    raw_token, record = create_registration_token()
    return {"token": raw_token, "expiresAt": record["expiresAt"]}


def set_mode(request: Request, mode: str) -> dict[str, Any]:
    if mode not in ("local", "remote"):
        raise HTTPException(status_code=422, detail="mode must be 'local' or 'remote'")
    if mode == "remote":
        check_limit(request, "max_remote_runners", 0)
    config = read_app_config()
    config.setdefault("runners", {})["mode"] = mode
    write_app_config(config, "settings.runners.mode.updated")
    return {"ok": True, "mode": mode}


def update_settings(
    runner_id: str,
    *,
    max_concurrent: int | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    settings: dict[str, Any] = {}
    if max_concurrent is not None:
        settings["maxConcurrent"] = max_concurrent
    if name is not None:
        settings["name"] = name
    if not settings:
        raise HTTPException(status_code=422, detail="No settings provided")
    updated = _update_runner_settings(runner_id, settings)
    if updated is None:
        raise HTTPException(status_code=404, detail="Runner not found")
    updated["computedStatus"] = compute_runner_status(updated)
    return _runner_to_dict(updated)


def approve(request: Request, runner_id: str) -> dict[str, Any]:
    all_runners = list_runners_with_status()
    approved_count = sum(1 for r in all_runners if r.get("status") == "approved")
    check_limit(request, "max_remote_runners", approved_count)
    if _approve_runner(runner_id) is None:
        raise HTTPException(status_code=404, detail="Runner not found")
    return {"ok": True}


def revoke(runner_id: str) -> dict[str, Any]:
    if _revoke_runner(runner_id) is None:
        raise HTTPException(status_code=404, detail="Runner not found")
    return {"ok": True}


def remove(runner_id: str) -> dict[str, Any]:
    if not _remove_runner(runner_id):
        raise HTTPException(status_code=404, detail="Runner not found")
    return {"ok": True}


def rotate_token(runner_id: str) -> dict[str, Any]:
    new_token, error = rotate_auth_token(runner_id)
    if error:
        raise HTTPException(status_code=404, detail=error)
    return {"ok": True, "newToken": new_token}
