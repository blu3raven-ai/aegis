"""REST endpoints for repos asset management — Phase 27.

Provides:
  GET /api/v1/repos          — list monitored repos with scan coverage summary
  GET /api/v1/repos/{id}     — detail for a single repo (org%2Frepo encoded)
"""
from __future__ import annotations

import urllib.parse
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from src.repos.service import RepoService, RepoSummary, RepoDetail
from src.settings.router import require_permission

router = APIRouter(prefix="/api/v1/repos", tags=["repos"])


def _summary_to_dict(s: RepoSummary) -> dict[str, Any]:
    return {
        "repo_id": s.repo_id,
        "org": s.org,
        "repo": s.repo,
        "last_scanned_sha": s.last_scanned_sha,
        "manifest_set_hash": s.manifest_set_hash,
        "last_scanned_at": s.last_scanned_at.isoformat() if s.last_scanned_at else None,
        "findings_count_by_severity": s.findings_count_by_severity,
        "chains_count": s.chains_count,
        "scanners_with_coverage": s.scanners_with_coverage,
        "coverage_status": s.coverage_status,
        "source_url": s.source_url,
    }


def _detail_to_dict(d: RepoDetail) -> dict[str, Any]:
    base = _summary_to_dict(d)
    base["scan_history"] = [
        {
            "scan_id": r.scan_id,
            "scanner_type": r.scanner_type,
            "status": r.status,
            "started_at": r.started_at,
            "duration_ms": r.duration_ms,
            "findings_count": r.findings_count,
        }
        for r in d.scan_history
    ]
    base["active_findings"] = [
        {
            "id": f.id,
            "tool": f.tool,
            "severity": f.severity,
            "state": f.state,
            "identity_key": f.identity_key,
            "repo": f.repo,
            "first_seen_at": f.first_seen_at,
            "last_seen_at": f.last_seen_at,
        }
        for f in d.active_findings
    ]
    base["attached_chains"] = [
        {
            "id": c.id,
            "chain_type": c.chain_type,
            "severity": c.severity,
            "status": c.status,
            "created_at": c.created_at,
        }
        for c in d.attached_chains
    ]
    base["default_branch"] = d.default_branch
    return base


@router.get("")
def list_repos(
    request: Request,
    org_id: str | None = None,
    since_days: int | None = None,
    has_critical: bool | None = None,
    limit: int = 100,
) -> JSONResponse:
    """List all monitored repos with coverage and risk summary."""
    require_permission(request, "view_findings")
    summaries = RepoService.list_repos(
        org_id=org_id,
        since_days=since_days,
        has_critical=has_critical,
        limit=limit,
    )
    return JSONResponse({"repos": [_summary_to_dict(s) for s in summaries]})


@router.get("/{repo_id:path}")
def get_repo(
    request: Request,
    repo_id: str,
) -> JSONResponse:
    """Return detail for a single repo. repo_id is URL-encoded org%2Frepo."""
    require_permission(request, "view_findings")
    decoded = urllib.parse.unquote(repo_id)
    parts = decoded.split("/", 1)
    if len(parts) != 2:
        return JSONResponse({"error": "repo_id must be org/repo"}, status_code=400)
    org, repo_name = parts
    detail = RepoService.get_repo(org, repo_name)
    if detail is None:
        return JSONResponse({"error": "repo not found"}, status_code=404)
    return JSONResponse(_detail_to_dict(detail))
