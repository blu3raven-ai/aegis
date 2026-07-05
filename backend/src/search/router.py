"""Global search REST endpoint — Phase 28.

GET /api/v1/search?q=<query>&scope=findings,repos&limit=50
Returns grouped results across findings, repos, audit events,
and notification destinations.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from src.search.service import SearchService, VALID_SCOPES

router = APIRouter(prefix="/api/v1/search", tags=["search"])

_service = SearchService()


@router.get("")
def global_search(
    request: Request,
    q: str = Query(default="", min_length=0),
    scope: list[str] = Query(default_factory=list),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    """Search across findings, repos, audit events, and destinations.

    Results are scoped to the requesting user's org (passed via the `org`
    query parameter, defaulting to all accessible orgs). Only authenticated
    users can reach this endpoint (JWT/API-key middleware enforces that at the
    FastAPI application level).
    """
    query = q.strip()
    if not query:
        return JSONResponse(
            content={"query": "", "total": 0, "grouped": {}, "duration_ms": 0}
        )

    # Parse comma-separated scopes sent as a single string, e.g. scope=findings,repos
    parsed_scopes: list[str] = []
    for s in scope:
        parsed_scopes.extend(part.strip() for part in s.split(",") if part.strip())

    active_scopes = (
        [s for s in parsed_scopes if s in VALID_SCOPES] or None
    )

    # org_id is optional — if omitted, all accessible orgs are searched
    org_id: str | None = request.query_params.get("org_id") or None

    results = _service.search(
        query,
        scopes=active_scopes,
        org_id=org_id,
        limit=limit,
    )

    return {
        "query": results.query,
        "total": results.total,
        "grouped": {
            group: [_hit_to_dict(h) for h in hits]
            for group, hits in results.grouped.items()
        },
        "duration_ms": results.duration_ms,
    }


def _hit_to_dict(hit) -> dict[str, Any]:
    return {
        "type": hit.type,
        "id": hit.id,
        "title": hit.title,
        "subtitle": hit.subtitle,
        "href": hit.href,
        "score": hit.score,
        "metadata": hit.metadata,
    }
