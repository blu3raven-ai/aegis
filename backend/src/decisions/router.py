"""CI gate decision endpoint."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from src.authz.enforcement.dependencies import Permission
from src.authz.enforcement.scope import resolve_asset_ids_from_request
from src.authz.permissions.catalog import VIEW_FINDINGS
from src.db.engine import get_session
from src.decisions.service import DecisionService, parse_policy

router = APIRouter(prefix="/api/v1/findings/decisions", tags=["findings"])

_service = DecisionService()


class DecisionRequest(BaseModel):
    repo: str | None = Field(None, description="Optional repo (org/name) to narrow the decision.")
    policy: dict[str, Any] | None = Field(
        None,
        description="Optional policy override; defaults to {block_on: ['critical']}.",
    )


@router.post("")
async def evaluate_decision(
    payload: DecisionRequest,
    request: Request,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> dict[str, Any]:
    """Return a Go/No-Go verdict scoped to the caller's accessible assets.

    Authorization: VIEW_FINDINGS plus the caller's asset-scope set, derived
    from team membership and direct grants via
    ``resolve_asset_ids_from_request``. The ``repo`` body field narrows the
    decision within the caller's scope; it cannot widen access. Empty scope
    is fail-closed (403) so unauthorized callers cannot fish for a "pass"
    verdict against an empty finding set.

    The legacy ``org_id`` body field has been removed — it was a BOLA vector
    that let any caller with VIEW_FINDINGS supply an arbitrary org and have
    the service evaluate findings outside their actual scope. Callers that
    used to depend on it now get the scoped verdict implicitly via session
    grants (interactive users) or the API key's bound user (machine clients).
    """
    asset_ids = await resolve_asset_ids_from_request(request)
    if not asset_ids:
        raise HTTPException(status_code=403, detail="No accessible assets")

    try:
        policy = parse_policy(payload.policy)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        async with get_session() as session:
            return await _service.evaluate(
                asset_ids=asset_ids,
                repo=payload.repo,
                policy=policy,
                session=session,
            )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
