"""Dependency Scanning API endpoints.

Docker-based scanning using Syft/Grype. Mirrors the secret scanning
orchestration pattern: start run -> docker scan -> ingest -> serve dashboard.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from src.shared.lifecycle import VALID_DISMISS_REASONS, dismiss_finding, reopen_finding, bulk_dismiss
from src.dependencies.lifecycle import dependencies_hooks
from src.license.limits import check_feature, get_tier
from src.license.types import TIER_LIMITS
from src.dependencies.scanner import InMemoryScanRuntime, execute_dependencies_scan_once, now_iso
from src.settings.router import require_permission, has_permission
from src.settings.team_access import actor_user_id
from src.shared.checkpoints import compute_coverage_gaps
from src.shared.config import build_source_repo_list, get_token_for_org, get_dependencies_scanner_config, get_scan_sources_for_org, org_has_source_connections
from src.shared.scan_orchestration import start_multi_org_scan, cancel_multi_org_scan
from src.shared.rate_limit import rate_limit_scan
from src.shared.router_helpers import require_orgs, api_error, validate_org
from src.storage import (
    create_dependencies_run,
    list_dependencies_runs,
    update_dependencies_run,
)
from src.db.helpers import run_db
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession


router = APIRouter(prefix="/dependencies/api", tags=["dependencies"])

_dependencies_runtime = InMemoryScanRuntime()




@router.get("/history")
def get_history(request: Request, orgs: list[str] = Depends(require_orgs)) -> dict[str, Any]:
    if not has_permission(request, "view_scan_history"):
        return {"history": [], "coverageGaps": []}
    all_runs: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    for org_name in orgs:
        all_runs.extend(_enrich_run(r) or r for r in list_dependencies_runs(org_name))
        expected = [r["full_name"] for r in build_source_repo_list(get_scan_sources_for_org(org_name))]
        if expected:
            coverage_gaps.extend(compute_coverage_gaps("dependencies", org_name, expected))
    all_runs.sort(key=lambda r: r.get("createdAt", ""), reverse=True)
    return {"history": all_runs[:20], "coverageGaps": coverage_gaps}


def _enrich_run(run: dict[str, Any] | None) -> dict[str, Any] | None:
    """Add computed fields like durationSeconds to a run record."""
    if not run:
        return None
    started = run.get("startedAt")
    finished = run.get("finishedAt")
    if isinstance(started, str) and isinstance(finished, str):
        try:
            from datetime import datetime
            s = datetime.fromisoformat(started.replace("Z", "+00:00"))
            f = datetime.fromisoformat(finished.replace("Z", "+00:00"))
            run["durationSeconds"] = max(0, int((f - s).total_seconds()))
        except (ValueError, TypeError):
            pass
    return run


@router.get("/runs/latest")
async def get_latest_run(request: Request, orgs: list[str] = Depends(require_orgs)) -> dict[str, Any]:
    if not has_permission(request, "view_scan_history"):
        return {"latest": None, "lastCompleted": None}
    all_runs: list[dict[str, Any]] = []
    for org_name in orgs:
        all_runs.extend(list_dependencies_runs(org_name))
    all_runs.sort(key=lambda r: r.get("createdAt", ""), reverse=True)
    # Prefer the actively-running run (has progress) over a queued/idle one
    active_run = next((r for r in all_runs if r.get("status") in ("queued", "running", "ingesting")), None)
    latest = _enrich_run(active_run or (all_runs[0] if all_runs else None))
    last_completed = _enrich_run(next((r for r in all_runs if r.get("status") in ("completed", "completed_with_merge_error")), None))
    from src.dependencies.sbom_store import any_sbom_for_asset_ids
    from src.shared.scope import resolve_asset_ids_from_request
    asset_ids = await resolve_asset_ids_from_request(request)
    return {"latest": latest, "lastCompleted": last_completed, "hasSboms": any_sbom_for_asset_ids(asset_ids)}


@router.post("/runs")
def start_runs(
    request: Request,
    orgs: list[str] = Depends(require_orgs),
    mode: str | None = Query(None),
    scan_mode: str = Query("full"),
) -> JSONResponse:
    require_permission(request, "run_scans")
    rate_limit_scan(request, "dependencies")

    incremental_mode: Literal["full", "incremental"] | None = None
    if mode in ("full", "incremental"):
        incremental_mode = mode  # type: ignore[assignment]

    VALID_SCAN_MODES = {"full", "sbom_only", "advisories_only"}
    if scan_mode not in VALID_SCAN_MODES:
        return api_error(f"Invalid scan_mode. Must be one of: {', '.join(sorted(VALID_SCAN_MODES))}", 400)

    scanner_config = get_dependencies_scanner_config()
    payload, status = start_multi_org_scan(
        orgs=orgs,
        runtime=_dependencies_runtime,
        create_run_fn=create_dependencies_run,
        execute_fn=execute_dependencies_scan_once,
        execute_kwargs={"scanner_config": scanner_config, "mode": incremental_mode, "scan_mode": scan_mode},
        source_category="code-repositories",
        tool_label="dependency",
        update_run_fn=update_dependencies_run,
        skip_connection_check=(scan_mode == "advisories_only"),
    )
    if status == 202:
        from src.shared.event_emit_helpers import emit_manual_rescan
        for org in orgs:
            emit_manual_rescan(
                org_id=org,
                repo_id=None,
                scanner_type="dependencies",
                full=(scan_mode == "full"),
                source_component="dependencies.router",
            )
    return JSONResponse(payload, status_code=status)


@router.post("/runs/cancel")
def cancel_runs(
    request: Request,
    orgs: list[str] = Depends(require_orgs),
) -> JSONResponse:
    require_permission(request, "cancel_scans")
    return JSONResponse(cancel_multi_org_scan(orgs, _dependencies_runtime, update_dependencies_run, "dependencies"))


@router.patch("/findings/review")
async def bulk_review_findings(request: Request) -> JSONResponse:
    require_permission(request, "run_scans")
    body = await request.json()
    org = body.get("org")
    identity_keys = body.get("identityKeys", [])
    action = body.get("action")  # "dismiss" or "reopen"
    reason = body.get("reason")  # required for dismiss

    if not org or not identity_keys or action not in ("dismiss", "reopen"):
        return api_error("Missing org, identityKeys, or valid action", 400)
    validate_org(org)
    if len(identity_keys) > 1000:
        return api_error("Too many identity keys (max 1000 per request)", 400)
    if action == "dismiss" and reason not in VALID_DISMISS_REASONS:
        return api_error("Invalid dismiss reason", 400)

    user_id = actor_user_id(request) or "unknown"

    from src.db.engine import async_session_factory
    from src.shared.scope import resolve_asset_ids_for_org
    async with async_session_factory() as db:
        asset_ids = await resolve_asset_ids_for_org(db, org, asset_type="repo")

    updated = 0
    if action == "dismiss":
        updated = bulk_dismiss(
            "dependencies", identity_keys, reason, user_id, asset_ids=asset_ids,
        )
    else:
        for key in identity_keys:
            for asset_id in asset_ids:
                reopen_finding("dependencies", key, user_id, asset_id=asset_id)
            updated += 1

    return JSONResponse({"ok": True, "updated": updated})


@router.post("/findings/dismiss")
async def dismiss_finding_endpoint(request: Request) -> JSONResponse:
    require_permission(request, "run_scans")
    body = await request.json()
    org = body.get("org")
    identity_key = body.get("identityKey")
    reason = body.get("reason")
    if not org or not identity_key or not reason:
        return api_error("Missing org, identityKey, or reason", 400)
    validate_org(org)
    if reason not in VALID_DISMISS_REASONS:
        return api_error(f"Invalid dismiss reason. Must be one of: {sorted(VALID_DISMISS_REASONS)}", 400)
    user_id = actor_user_id(request) or "unknown"
    from src.db.engine import async_session_factory
    from src.shared.scope import resolve_asset_ids_for_org
    async with async_session_factory() as db:
        asset_ids = await resolve_asset_ids_for_org(db, org, asset_type="repo")
    for asset_id in asset_ids:
        dismiss_finding("dependencies", identity_key, reason, user_id, asset_id=asset_id)

    return JSONResponse({"ok": True})


@router.post("/findings/reopen")
async def reopen_finding_endpoint(request: Request) -> JSONResponse:
    require_permission(request, "run_scans")
    body = await request.json()
    org = body.get("org")
    identity_key = body.get("identityKey")
    if not org or not identity_key:
        return api_error("Missing org or identityKey", 400)
    validate_org(org)
    user_id = actor_user_id(request) or "unknown"
    from src.db.engine import async_session_factory
    from src.shared.scope import resolve_asset_ids_for_org
    async with async_session_factory() as db:
        asset_ids = await resolve_asset_ids_for_org(db, org, asset_type="repo")
    for asset_id in asset_ids:
        reopen_finding("dependencies", identity_key, user_id, asset_id=asset_id)

    return JSONResponse({"ok": True})
