"""SAST (Static Application Security Testing) API endpoints.

Docker-based scanning using Opengrep. Mirrors the SCA scanning
orchestration pattern: start run -> docker scan -> ingest -> serve dashboard.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from src.shared.lifecycle import VALID_DISMISS_REASONS, dismiss_finding, reopen_finding, bulk_dismiss
from src.code_scanning.lifecycle import code_scanning_hooks
from src.code_scanning.scanner import InMemoryScanRuntime, execute_code_scanning_scan_once, now_iso
from src.settings.router import require_permission, has_permission
from src.settings.team_access import actor_user_id
from src.shared.config import get_github_token_for_org, get_code_scanning_scanner_config, org_has_source_connections
from src.shared.scan_orchestration import start_multi_org_scan, cancel_multi_org_scan
from src.shared.rate_limit import rate_limit_scan, rate_limit_by_ip
from src.shared.router_helpers import require_orgs, api_error, validate_org
from src.storage import (
    create_code_scanning_run,
    list_code_scanning_runs,
    read_code_scanning_findings,
    update_code_scanning_run,
)


router = APIRouter(prefix="/code-scanning/api", tags=["code-scanning"])

_code_scanning_runtime = InMemoryScanRuntime()


def _slim_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Strip finding to frontend-safe shape."""
    return {
        "identity_key": code_scanning_hooks.compute_identity_key(finding),
        "repo_full_name": finding.get("repo_full_name", ""),
        "repo_html_url": finding.get("repo_html_url", ""),
        "file_path": finding.get("file_path", ""),
        "start_line": finding.get("start_line", 0),
        "end_line": finding.get("end_line", 0),
        "rule_id": finding.get("rule_id", ""),
        "rule_name": finding.get("rule_name", ""),
        "severity": finding.get("severity", ""),
        "confidence": finding.get("confidence", ""),
        "category": finding.get("category", ""),
        "cwe": finding.get("cwe", []),
        "message": finding.get("message", ""),
        "snippet": finding.get("snippet", ""),
        "fix_suggestion": finding.get("fix_suggestion"),
        "state": finding.get("state", "open"),
        "first_seen_at": finding.get("first_seen_at"),
        "fixed_at": finding.get("fixed_at"),
        "dismissed_at": finding.get("dismissed_at"),
        "dismissed_by": finding.get("dismissed_by"),
        "dismissed_reason": finding.get("dismissed_reason"),
        "ai_review": finding.get("ai_review"),
        "language": finding.get("language"),
        "file_class": finding.get("file_class"),
        "code_window": finding.get("code_window"),
        "code_flows": finding.get("code_flows"),
        "reachability": finding.get("reachability"),
    }



@router.get("/history")
def get_history(request: Request, orgs: list[str] = Depends(require_orgs)) -> dict[str, Any]:
    if not has_permission(request, "view_scan_history"):
        return {"history": []}
    all_runs: list[dict[str, Any]] = []
    for org_name in orgs:
        all_runs.extend(list_code_scanning_runs(org_name))
    all_runs.sort(key=lambda r: r.get("createdAt", ""), reverse=True)
    return {"history": all_runs[:20]}


@router.get("/runs/latest")
def get_latest_run(request: Request, orgs: list[str] = Depends(require_orgs)) -> dict[str, Any]:
    if not has_permission(request, "view_scan_history"):
        return {"latest": None, "lastCompleted": None}
    all_runs: list[dict[str, Any]] = []
    for org_name in orgs:
        all_runs.extend(list_code_scanning_runs(org_name))
    all_runs.sort(key=lambda r: r.get("createdAt", ""), reverse=True)
    active_run = next((r for r in all_runs if r.get("status") in ("queued", "running", "ingesting")), None)
    latest = active_run or (all_runs[0] if all_runs else None)
    last_completed = next((r for r in all_runs if r.get("status") == "completed"), None)
    return {"latest": latest, "lastCompleted": last_completed}


VALID_SCAN_MODES = {"full", "rules_only", "ai_review_only"}


@router.post("/runs")
def start_runs(
    request: Request,
    orgs: list[str] = Depends(require_orgs),
    scan_mode: str = Query("full"),
) -> JSONResponse:
    require_permission(request, "run_scans")
    rate_limit_scan(request, "code_scanning")

    if scan_mode not in VALID_SCAN_MODES:
        return api_error("Invalid scan_mode. Must be one of: full, rules_only, ai_review_only", 400)

    scanner_config = get_code_scanning_scanner_config()

    if scan_mode == "ai_review_only":
        ai_enabled = scanner_config.get("aiReviewEnabled") or scanner_config.get("aiEndpoint")
        if not ai_enabled:
            return api_error("AI review is not configured. Set up an AI endpoint in Code Scanning settings.", 400)

    payload, status = start_multi_org_scan(
        orgs=orgs,
        runtime=_code_scanning_runtime,
        create_run_fn=create_code_scanning_run,
        execute_fn=execute_code_scanning_scan_once,
        execute_kwargs={"scanner_config": scanner_config, "scan_mode": scan_mode},
        source_category="code-repositories",
        tool_label="Code Scanning",
        update_run_fn=update_code_scanning_run,
        skip_connection_check=(scan_mode == "ai_review_only"),
    )
    return JSONResponse(payload, status_code=status)


@router.post("/runs/cancel")
def cancel_runs(
    request: Request,
    orgs: list[str] = Depends(require_orgs),
) -> JSONResponse:
    require_permission(request, "cancel_scans")
    return JSONResponse(cancel_multi_org_scan(orgs, _code_scanning_runtime, update_code_scanning_run, "code_scanning"))


@router.patch("/findings/review")
async def bulk_review_findings(request: Request) -> JSONResponse:
    require_permission(request, "run_scans")
    body = await request.json()
    org = body.get("org")
    identity_keys = body.get("identityKeys", [])
    action = body.get("action")
    reason = body.get("reason")

    MAX_BULK_KEYS = 1000
    if not org or not identity_keys or action not in ("dismiss", "reopen"):
        return api_error("Missing org, identityKeys, or valid action", 400)
    validate_org(org)
    if not isinstance(identity_keys, list) or len(identity_keys) > MAX_BULK_KEYS:
        return api_error(f"identityKeys must be a list of at most {MAX_BULK_KEYS} items", 400)
    if action == "dismiss" and reason not in VALID_DISMISS_REASONS:
        return api_error("Invalid dismiss reason", 400)

    user_id = actor_user_id(request) or "unknown"

    updated = 0
    if action == "dismiss":
        updated = bulk_dismiss("code_scanning", org, identity_keys, reason, user_id)
    else:
        for key in identity_keys:
            reopen_finding("code_scanning", org, key, user_id)
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
    dismiss_finding("code_scanning", org, identity_key, reason, user_id)

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
    reopen_finding("code_scanning", org, identity_key, user_id)

    return JSONResponse({"ok": True})


@router.post("/findings/ai-review")
async def ai_review_finding_endpoint(request: Request) -> JSONResponse:
    require_permission(request, "run_scans")
    rate_limit_by_ip(request, 10, 60)
    body = await request.json()
    org = body.get("org")
    identity_key = body.get("identityKey")
    if not org or not identity_key:
        return api_error("Missing org or identityKey", 400)

    from src.shared.config import read_app_config

    config = read_app_config()
    sast_config = (config.get("tools") or {}).get("codeScanning") or {}
    if not sast_config.get("aiReviewEnabled"):
        return api_error("AI review is not enabled", 400)

    findings = read_code_scanning_findings(org)
    if not findings:
        return api_error("No findings found", 404)

    target_finding = None
    for finding in findings:
        if code_scanning_hooks.compute_identity_key(finding) == identity_key:
            target_finding = finding
            break

    if not target_finding:
        return api_error("Finding not found", 404)

    try:
        from src.code_scanning.ai_review import review_code_scanning_finding, CodeScanningAiReviewError
        result = await review_code_scanning_finding(target_finding, sast_config)
    except CodeScanningAiReviewError as e:
        return api_error(str(e), 400)
    except Exception as e:
        import logging
        logging.getLogger(__name__).exception("AI review failed for %s: %s", identity_key, e)
        return api_error("AI review failed", 500)

    from src.storage import patch_finding_detail
    patch_finding_detail("code_scanning", org, identity_key, {"aiReview": result})
    return JSONResponse({"ok": True, "review": result})
