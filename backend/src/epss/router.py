"""EPSS scores API router.

Endpoints:
  GET  /api/v1/sla/epss/scores/{cve}   — single EPSS score lookup
  GET  /api/v1/sla/epss/top            — open findings ranked by EPSS for the caller's scope

Refresh lives on the enrichment surface — see backend/src/enrichment/router.py.

Route handlers are synchronous (FastAPI runs them in a thread pool) because
EpssService uses run_db() internally — consistent with kev/router.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from src.authz.enforcement.dependencies import Permission
from src.authz.enforcement.scope import resolve_asset_ids_from_request
from src.authz.permissions.catalog import VIEW_FINDINGS
from src.epss.service import EpssService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sla/epss", tags=["sla"])

_service = EpssService()


def _score_dict(s) -> dict:
    return {
        "cve": s.cve,
        "score": s.score,
        "percentile": s.percentile,
        "scored_date": s.scored_date.isoformat() if s.scored_date else None,
        "fetched_at": s.fetched_at.isoformat() if s.fetched_at else None,
    }


@router.get("/scores/{cve}")
def get_score(cve: str) -> JSONResponse:
    """Fetch the latest EPSS score for a single CVE (e.g. CVE-2024-12345)."""
    score = _service.get_score(cve)
    if score is None:
        raise HTTPException(status_code=404, detail=f"{cve} is not in the EPSS feed")
    return JSONResponse(_score_dict(score))


@router.get("/top")
async def top_findings(
    request: Request,
    limit: int = Query(default=20, ge=1, le=200),
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> JSONResponse:
    """List open findings ranked by EPSS score, descending, scoped to the caller.

    Authorization: VIEW_FINDINGS plus the caller's asset-scope set (team
    grants + direct grants). Empty scope returns an empty list rather than
    leaking that the endpoint exists or accepting a client-supplied org_id
    as scope override — the previous ``?org_id=`` query-param fallback was
    a BOLA vector.
    """
    asset_ids = await resolve_asset_ids_from_request(request)
    if not asset_ids:
        return JSONResponse({"findings": [], "count": 0})
    findings = _service.top_findings_by_epss(asset_ids=asset_ids, limit=limit)
    return JSONResponse({"findings": findings, "count": len(findings)})
