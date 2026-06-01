"""POST /api/v1/decisions/go-no-go — backend-authorised CI gate decision.

Spec §6.1. Replaces the CLI's local heuristic fallback so all clients see
the same answer regardless of which deploy path they hit.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.db.engine import get_session
from src.decisions.service import DecisionService, parse_policy

router = APIRouter(prefix="/api/v1/decisions", tags=["decisions"])

_service = DecisionService()


class DecisionRequest(BaseModel):
    org_id: str = Field(..., min_length=1, description="Org the decision is scoped to.")
    repo: str | None = Field(None, description="Optional repo (org/name) to narrow the decision.")
    policy: dict[str, Any] | None = Field(
        None,
        description="Optional policy override; defaults to {block_on: ['critical']}.",
    )


@router.post("/go-no-go")
async def go_no_go(payload: DecisionRequest) -> dict[str, Any]:
    """Return a Go/No-Go verdict for an org (optionally narrowed to a repo).

    Per-org isolation is mandatory — there is no cross-org admin override on
    this endpoint. Bad policy shapes surface as 400 so CI pipelines fail
    loudly rather than silently treating malformed input as default.
    """
    try:
        policy = parse_policy(payload.policy)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        async with get_session() as session:
            return await _service.evaluate(
                org_id=payload.org_id,
                repo=payload.repo,
                policy=policy,
                session=session,
            )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
