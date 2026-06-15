from __future__ import annotations

import threading
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.settings.router import require_permission, has_permission
from src.settings.team_access import actor_user_id, actor_global_role, user_has_repository_access
from src.settings.organisations_store import list_teams
from src.settings.direct_access_store import list_direct_grants
from src.shared.config import get_token_for_org, get_secret_scanner_config
from src.shared.router_helpers import require_orgs, filter_by_user_scope
from src.secrets.pool import read_checkpoints as read_scan_checkpoints
from src.secrets.scanner import execute_secret_scan_once, InMemoryScanRuntime, mark_run_cancelled
from src.storage import read_secret_run, read_secrets_snapshot

from src.secrets.service_analytics import build_review_queue_payload, build_insights_payload, build_health_payload
from src.secrets.service_preview import build_code_preview_payload
from src.secrets.service_review import apply_review_updates
from src.secrets.service_runs import get_runtime, list_runs_payload, latest_run_payload, start_secret_runs, cancel_secret_runs
from src.shared.rate_limit import rate_limit_scan
from src.shared.ttl_cache import TtlCache

router = APIRouter(prefix="/api/v1/secrets", tags=["secrets"])

_cache = TtlCache(ttl_seconds=300)


def _invalidate_cache(org: str | None = None) -> None:
    _cache.invalidate(f"cache:{org}" if org else None)


# ── Request models ───────────────────────────────────────────────────────────

class ReviewUpdate(BaseModel):
    fingerprint: str | None = None
    status: str | None = None
    secretIdentity: str | None = None
    scope: str | None = None
    repository: str | None = None
    source: str | None = None
    detector: str | None = None
    filePath: str | None = None
    line: int | None = None
    commit: str | None = None


class ReviewPatch(BaseModel):
    org: str | None = None
    updates: list[ReviewUpdate] | None = None


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/review-queue")
def get_review_queue(request: Request, orgs: list[str] = Depends(require_orgs)) -> Any:
    if not has_permission(request, "view_findings"):
        return {"queue": [], "empty": True}
    payload = build_review_queue_payload(orgs)
    if "queue" in payload:
        payload["queue"] = filter_by_user_scope(request, payload["queue"])
        payload["empty"] = len(payload["queue"]) == 0
    return payload


@router.get("/insights")
def get_insights(
    request: Request,
    orgs: list[str] = Depends(require_orgs),
    source: str | None = Query(default=None),
    organization: str | None = Query(default=None, alias="filterOrg"),
) -> Any:
    if not has_permission(request, "view_findings"):
        return {"triagePriority": [], "detectorBreakdown": [], "sourceBreakdown": []}
    from src.license.limits import check_feature
    check_feature(request, "insights_tab")
    payload = build_insights_payload(orgs, source_filter=source, organization_filter=organization)
    if "triagePriority" in payload:
        payload["triagePriority"] = filter_by_user_scope(request, payload["triagePriority"])
    return payload


@router.get("/health")
def get_health(request: Request, orgs: list[str] = Depends(require_orgs)) -> Any:
    if not has_permission(request, "view_findings"):
        return {"coverageGaps": [], "scanFrequency": []}
    from src.license.limits import check_feature
    check_feature(request, "health_tab")
    payload = build_health_payload(orgs, read_checkpoints=lambda org_name: read_scan_checkpoints())
    if "coverageGaps" in payload:
        payload["coverageGaps"] = filter_by_user_scope(request, payload["coverageGaps"], org_key="repository", repo_key="repository")
    return payload


@router.get("/runs")
def get_runs(request: Request, orgs: list[str] = Depends(require_orgs)) -> Any:
    if not has_permission(request, "view_scan_history"):
        return {"runs": []}
    return list_runs_payload(orgs)


@router.post("/runs")
def start_runs(
    request: Request,
    orgs: list[str] = Depends(require_orgs),
    scanDepth: Literal["light", "deep"] | None = Query(default=None),
) -> Any:
    require_permission(request, "run_scans")
    rate_limit_scan(request, "secrets")

    org_run_queue: list[tuple[str, str, str, InMemoryScanRuntime, dict[str, str], str | None]] = []

    def collect_run(
        org_name: str, run_id: str, token: str,
        runtime: InMemoryScanRuntime, scanner_config: dict[str, str],
        _scan_depth: str | None,
    ) -> None:
        org_run_queue.append((org_name, run_id, token, runtime, scanner_config, _scan_depth))

    payload, status_code = start_secret_runs(
        orgs, scan_depth=scanDepth, runtime_getter=get_runtime,
        run_launcher=collect_run, get_token_for_org=get_token_for_org,
        get_scanner_config=get_secret_scanner_config,
    )

    if status_code == 202 and org_run_queue:
        captured_queue = list(org_run_queue)

        def run_sequentially() -> None:
            remaining = list(captured_queue)
            for i, (org_name, run_id, token, runtime, scanner_config, scan_depth) in enumerate(remaining):
                record = read_secret_run(org_name, run_id)
                if record and record.get("status") == "cancelled":
                    continue
                from src.shared.config import get_source_type_for_org
                source_type = get_source_type_for_org(org_name, "code-repositories")
                execute_secret_scan_once(org_name, token, run_id, source_type=source_type, runtime=runtime, scanner_config=scanner_config, scan_depth=scan_depth)
                _invalidate_cache(org_name)
                record = read_secret_run(org_name, run_id)
                if record and record.get("status") == "cancelled":
                    for rem_org, rem_run_id, *_ in remaining[i + 1:]:
                        rem_record = read_secret_run(rem_org, rem_run_id)
                        if rem_record and rem_record.get("status") not in ("cancelled", "completed"):
                            mark_run_cancelled(rem_org, rem_run_id)
                    break

        threading.Thread(target=run_sequentially, daemon=True).start()

        from src.shared.event_emit_helpers import emit_manual_rescan
        for org in orgs:
            emit_manual_rescan(
                repo_id=None,
                scanner_type="secrets",
                full=False,
                source_component="secrets.router",
            )

    if "error" in payload:
        return JSONResponse({"error": str(payload["error"])}, status_code=status_code)
    return JSONResponse(payload, status_code=status_code)


@router.get("/runs/latest")
def get_latest_run(request: Request, org: str | None = None) -> Any:
    if not has_permission(request, "view_scan_history"):
        return {"latest": None, "lastCompleted": None}
    if not org:
        raise HTTPException(status_code=400, detail="Missing org parameter")
    return latest_run_payload(org)


@router.post("/runs/cancel")
def cancel_runs(request: Request, orgs: list[str] = Depends(require_orgs)) -> Any:
    require_permission(request, "run_scans")
    payload, status_code = cancel_secret_runs(orgs, runtime_getter=get_runtime)
    if "error" in payload:
        return JSONResponse({"error": str(payload["error"])}, status_code=status_code)
    return JSONResponse(payload, status_code=status_code)


@router.get("/code-preview")
def get_code_preview(
    request: Request,
    org: str | None = None,
    repo: str | None = None,
    fingerprint: str | None = None,
    commit: str | None = None,
    filePath: str | None = None,
    line: int | None = None,
) -> Any:
    if not has_permission(request, "manage_access_scope"):
        user_id = actor_user_id(request)
        teams = list_teams()
        direct_grants = list_direct_grants()
        if not user_has_repository_access(teams, user_id, org or "", repo or "", direct_grants=direct_grants):
            raise HTTPException(status_code=403, detail="Scope denied: repository access required")

    payload, status_code = build_code_preview_payload(
        org or "", repo or "", fingerprint or "", commit, filePath, line,
        get_token_for_org=get_token_for_org,
        read_secrets_snapshot=read_secrets_snapshot,
    )
    if "error" in payload:
        return JSONResponse({"error": str(payload["error"])}, status_code=status_code)
    return JSONResponse(payload, status_code=status_code)


@router.patch("/findings/review")
def patch_review(request: Request, payload: ReviewPatch) -> Any:
    require_permission(request, "review_findings")
    if len(payload.updates or []) > 1000:
        raise HTTPException(status_code=400, detail="Too many identity keys (max 1000 per request)")
    org = payload.org or ""
    response_payload, status_code = apply_review_updates(
        org,
        [update.model_dump() for update in (payload.updates or [])],
        user_id=actor_user_id(request),
        user_role=actor_global_role(request),
        user_role_id=getattr(request.state, "user_role_id", None),
    )
    if status_code == 200:
        _invalidate_cache(org)
    if "error" in response_payload:
        return JSONResponse({"error": str(response_payload["error"])}, status_code=status_code)
    return JSONResponse(response_payload, status_code=status_code)
