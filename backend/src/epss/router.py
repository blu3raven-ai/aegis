"""EPSS scores API router.

Endpoints:
  GET  /api/v1/epss/scores/{cve}   — single EPSS score lookup
  GET  /api/v1/epss/top            — open findings ranked by EPSS for an org
  POST /api/v1/epss/refresh        — trigger fetch + upsert (admin)

Route handlers are synchronous (FastAPI runs them in a thread pool) because
EpssService uses run_db() internally — consistent with kev/router.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from src.epss.service import EpssService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/epss", tags=["epss"])

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
def top_findings(
    org_id: str = Query(..., alias="org_id"),
    limit: int = Query(default=20, ge=1, le=200),
) -> JSONResponse:
    """List open findings for an org ranked by EPSS score, descending."""
    findings = _service.top_findings_by_epss(org_id, limit=limit)
    return JSONResponse({"findings": findings, "count": len(findings)})


@router.post("/refresh")
def trigger_refresh() -> JSONResponse:
    """Trigger an immediate EPSS feed fetch + upsert. Intended for admins.

    Fetch failures bubble up as 502 so the caller can decide to retry.
    """
    from src.jobs.epss_refresh import refresh_epss_scores

    try:
        result = refresh_epss_scores()
    except Exception as exc:
        logger.exception("epss refresh failed")
        raise HTTPException(status_code=502, detail=f"EPSS refresh failed: {exc}") from exc

    return JSONResponse(result)
