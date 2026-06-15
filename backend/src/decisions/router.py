"""POST /api/v1/decisions/go-no-go — backend-authorised CI gate decision.

Spec §6.1. Replaces the CLI's local heuristic fallback so all clients see
the same answer regardless of which deploy path they hit.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.db.engine import get_session
from src.decisions.service import DecisionService, parse_policy
from src.settings.router import require_permission

router = APIRouter(prefix="/api/v1/decisions", tags=["decisions"])

_service = DecisionService()


class DecisionRequest(BaseModel):
    org_id: str | None = Field(
        None,
        min_length=1,
        description=(
            "Optional org override. Ignored when the session attaches an org; "
            "kept for legacy single-tenant API-key callers."
        ),
    )
    repo: str | None = Field(None, description="Optional repo (org/name) to narrow the decision.")
    policy: dict[str, Any] | None = Field(
        None,
        description="Optional policy override; defaults to {block_on: ['critical']}.",
    )


def _resolve_org(request: Request, payload: DecisionRequest) -> str:
    org = getattr(request.state, "user_org", None) or payload.org_id
    if not org:
        raise HTTPException(status_code=400, detail="org_id is required")
    return org


@router.post("/go-no-go")
async def go_no_go(payload: DecisionRequest, request: Request) -> dict[str, Any]:
    """Return a Go/No-Go verdict for the caller's org (optionally narrowed to a repo).

    Per-org isolation is mandatory — there is no cross-org admin override on
    this endpoint. The session-attached org always wins; the body's `org_id`
    is honoured only when the session has no org (single-tenant API keys).
    Bad policy shapes surface as 400 so CI pipelines fail loudly rather than
    silently treating malformed input as default.
    """
    require_permission(request, "view_findings")
    org_id = _resolve_org(request, payload)

    try:
        policy = parse_policy(payload.policy)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        async with get_session() as session:
            return await _service.evaluate(
                org_id=org_id,
                repo=payload.repo,
                policy=policy,
                session=session,
            )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
