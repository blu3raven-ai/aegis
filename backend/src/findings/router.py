"""Findings REST router.

GET /api/v1/findings/summary returns the cross-scanner KPI counts that the
findings page renders. GET /api/v1/findings/assignable-users feeds the
finding-assignee picker. List reads remain on GraphQL
(Query.findingsSearch).

PATCH endpoints handle single and bulk mutations:

- PATCH /api/v1/findings/{id}     single-finding mutation
- PATCH /api/v1/findings          bulk mutation by ids[]

Both accept a unified body with any of: state, dismiss_reason, comment,
assignee_user_id. The handler routes to the appropriate lifecycle helper.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select

from src.db.engine import get_session
from src.db.models import Finding
from src.findings.service import (
    FIXED_WINDOW_DAYS,
    _finding_to_dict,
    assign_finding,
    list_assignable_users,
    summarize_findings,
)
from src.settings.audit_stream.service import record_event
from src.authz.enforcement import require_permission
from src.authz.enforcement.dependencies import Permission
from src.authz.teams.access import actor_user_id
from src.authz.permissions.catalog import REVIEW_FINDINGS, RUN_SCANS
from src.shared.lifecycle import (
    VALID_DISMISS_REASONS,
    bulk_dismiss_in_session,
    dismiss_finding,
    reopen_finding,
)
from src.shared.home_views_refresher import request_home_views_refresh
from src.authz.enforcement.scope import resolve_asset_ids_from_request

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

_VALID_STATE_TRANSITIONS = frozenset({"dismissed", "open"})
_MAX_BULK_IDS = 1000


def _extract_patch(body: dict[str, Any]) -> dict[str, Any]:
    """Pull and validate the four optional patch fields. Returns a dict with
    only the fields present in the body; `assignee_user_id` is preserved when
    explicitly null (to support unassign).
    """
    out: dict[str, Any] = {}

    if "state" in body:
        state = body.get("state")
        if state not in _VALID_STATE_TRANSITIONS:
            raise HTTPException(
                status_code=400,
                detail=f"state must be one of: {sorted(_VALID_STATE_TRANSITIONS)}",
            )
        out["state"] = state

    if "dismiss_reason" in body and body["dismiss_reason"] is not None:
        reason = body["dismiss_reason"]
        if reason not in VALID_DISMISS_REASONS:
            raise HTTPException(
                status_code=400,
                detail=f"dismiss_reason must be one of: {sorted(VALID_DISMISS_REASONS)}",
            )
        out["dismiss_reason"] = reason

    if "comment" in body and body["comment"] is not None:
        comment = body["comment"]
        if not isinstance(comment, str):
            raise HTTPException(status_code=400, detail="comment must be a string")
        out["comment"] = comment

    if "assignee_user_id" in body:
        raw = body["assignee_user_id"]
        if raw is not None and not isinstance(raw, str):
            raise HTTPException(
                status_code=400, detail="assignee_user_id must be a string or null"
            )
        out["assignee_user_id"] = raw

    if "state" not in out and "assignee_user_id" not in out:
        raise HTTPException(
            status_code=400,
            detail="body must include at least one of: state, assignee_user_id",
        )

    if out.get("state") == "dismissed" and "dismiss_reason" not in out:
        raise HTTPException(
            status_code=400,
            detail="dismiss_reason is required when state=dismissed",
        )

    return out


@router.get("/summary")
async def get_findings_summary(
    request: Request,
    _: None = Depends(Permission(REVIEW_FINDINGS)),
) -> dict[str, int]:
    """Return cross-scanner KPI counts for the findings page.

    Scope comes from the request's asset_ids (resolved via the standard scope
    dependency). Empty scope returns all zeros so the page can render before
    any sources are configured without an extra branch on the client.
    """
    asset_ids = await resolve_asset_ids_from_request(request)
    if not asset_ids:
        return {
            "open": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "fixed_recent": 0,
            "dismissed": 0,
            "fixed_window_days": FIXED_WINDOW_DAYS,
        }
    async with get_session() as session:
        return await summarize_findings(session=session, asset_ids=asset_ids)


@router.get("/assignable-users")
async def get_assignable_users(
    request: Request,
    q: str | None = None,
    limit: int = 20,
    _: None = Depends(Permission(REVIEW_FINDINGS)),
) -> dict[str, list[dict[str, str]]]:
    """Return active users matching `q` for finding-assignee pickers."""
    async with get_session() as session:
        users = await list_assignable_users(session, q=q, limit=limit)
    return {"users": users}


@router.patch("/{finding_id}")
async def patch_finding(finding_id: int, request: Request) -> dict[str, Any]:
    """Apply a unified mutation to a single finding.

    Body fields (all optional, but at least one of state/assignee_user_id must
    be present):
      - state: "dismissed" | "open"
      - dismiss_reason: required when state=dismissed
      - comment: optional commentary attached to the dismiss event
      - assignee_user_id: string user id, or null to clear
    """
    body = await request.json()
    patch = _extract_patch(body)

    # Permission gating preserves the existing per-operation contract:
    # state changes go through the scan-lifecycle permission while assignment
    # uses the review permission. The route enforces both up front so a single
    # request that touches both fields needs both permissions.
    if "state" in patch:
        require_permission(request, RUN_SCANS)
    if "assignee_user_id" in patch:
        require_permission(request, REVIEW_FINDINGS)

    asset_ids = await resolve_asset_ids_from_request(request)
    scope = set(asset_ids)

    async with get_session() as session:
        result = await session.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalars().first()

    # Secrets findings (asset_id IS NULL) have no per-source isolation and are
    # intentionally out of scope for this endpoint — match the previous
    # surface so callers don't see a behaviour change.
    if finding is None or not finding.asset_id or finding.asset_id not in scope:
        raise HTTPException(status_code=404, detail="Finding not found")

    user_id = actor_user_id(request) or "unknown"

    if patch.get("state") == "dismissed":
        dismiss_finding(
            finding.tool, finding.identity_key, patch["dismiss_reason"], user_id,
            patch.get("comment"), asset_id=finding.asset_id,
        )
        record_event(
            action="finding.dismissed",
            actor_user_id=user_id,
            target=str(finding_id),
            metadata={
                "tool": finding.tool,
                "identity_key": finding.identity_key,
                "asset_id": finding.asset_id,
                "dismiss_reason": patch["dismiss_reason"],
                "comment": patch.get("comment"),
            },
        )
    elif patch.get("state") == "open":
        reopen_finding(
            finding.tool, finding.identity_key, user_id, asset_id=finding.asset_id,
        )
        record_event(
            action="finding.reopened",
            actor_user_id=user_id,
            target=str(finding_id),
            metadata={
                "tool": finding.tool,
                "identity_key": finding.identity_key,
                "asset_id": finding.asset_id,
            },
        )

    payload: dict[str, Any] | None = None
    if "assignee_user_id" in patch:
        try:
            async with get_session() as session:
                updated, previous = await assign_finding(
                    finding_id, patch["assignee_user_id"], session, asset_ids,
                )
                payload = _finding_to_dict(updated)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        record_event(
            action="finding.assigned",
            actor_user_id=user_id,
            target=str(finding_id),
            metadata={"from": previous, "to": payload["assignee_user_id"]},
        )

    return {"ok": True, "finding": payload}


@router.patch("")
async def patch_findings_bulk(request: Request) -> dict[str, Any]:
    """Apply a unified mutation to many findings in one call.

    Body:
      - ids: list[int] — required, max 1000
      - state, dismiss_reason, comment, assignee_user_id — as in single-PATCH

    All groups are processed inside a single AsyncSession transaction so the
    operation is atomic — a failure on any group rolls everything back.
    """
    body = await request.json()
    raw_ids = body.get("ids")
    if not isinstance(raw_ids, list) or not raw_ids:
        raise HTTPException(status_code=400, detail="ids must be a non-empty list of finding ids")
    if len(raw_ids) > _MAX_BULK_IDS:
        raise HTTPException(
            status_code=400, detail=f"Too many ids (max {_MAX_BULK_IDS} per request)"
        )
    try:
        ids = [int(x) for x in raw_ids]
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="ids must be integers") from exc

    patch = _extract_patch(body)
    if "state" in patch:
        require_permission(request, RUN_SCANS)
    if "assignee_user_id" in patch:
        require_permission(request, REVIEW_FINDINGS)

    asset_ids = await resolve_asset_ids_from_request(request)
    scope = set(asset_ids)
    user_id = actor_user_id(request) or "unknown"

    updated_total = 0

    if not asset_ids:
        # Fail-closed: caller has no asset scope. Short-circuit before
        # touching the DB so we don't even count requested ids.
        return {"ok": True, "updated": 0}

    async with get_session() as session:
        # Belt-and-braces scope filtering:
        # - SQL: ``asset_id IN (asset_ids)`` keeps cross-tenant rows in
        #   Postgres rather than streaming them into Python only to drop
        #   them. With a 1000-id request that was up to 1000 wasted reads.
        # - Python: redundant in production but a defensive backstop if the
        #   SQL predicate ever gets dropped, regresses, or the scope set is
        #   mis-resolved. Also keeps the unit tests' simple Session mock
        #   semantics honest.
        result = await session.execute(
            select(Finding)
            .where(Finding.id.in_(ids))
            .where(Finding.asset_id.in_(asset_ids))
        )
        rows = result.scalars().all()
        in_scope = [f for f in rows if f.asset_id and f.asset_id in scope]

        if patch.get("state") == "dismissed":
            groups: dict[tuple[str, str], list[str]] = defaultdict(list)
            key_to_id: dict[tuple[str, str, str], int] = {}
            for f in in_scope:
                groups[(f.tool, f.asset_id)].append(f.identity_key)
                key_to_id[(f.tool, f.asset_id, f.identity_key)] = f.id
            for (tool, asset_id), keys in groups.items():
                updated_total += await bulk_dismiss_in_session(
                    session, tool, keys, patch["dismiss_reason"], user_id,
                    patch.get("comment"), asset_ids=[asset_id],
                )
                for key in keys:
                    fid = key_to_id.get((tool, asset_id, key))
                    record_event(
                        action="finding.dismissed",
                        actor_user_id=user_id,
                        target=str(fid) if fid is not None else None,
                        metadata={
                            "tool": tool,
                            "identity_key": key,
                            "asset_id": asset_id,
                            "dismiss_reason": patch["dismiss_reason"],
                            "comment": patch.get("comment"),
                            "bulk": True,
                        },
                    )
        elif patch.get("state") == "open":
            for f in in_scope:
                reopen_finding(f.tool, f.identity_key, user_id, asset_id=f.asset_id)
                updated_total += 1
                record_event(
                    action="finding.reopened",
                    actor_user_id=user_id,
                    target=str(f.id),
                    metadata={
                        "tool": f.tool,
                        "identity_key": f.identity_key,
                        "asset_id": f.asset_id,
                        "bulk": True,
                    },
                )

        if "assignee_user_id" in patch:
            for f in in_scope:
                _, previous = await assign_finding(
                    f.id, patch["assignee_user_id"], session, asset_ids,
                )
                record_event(
                    action="finding.assigned",
                    actor_user_id=user_id,
                    target=str(f.id),
                    metadata={"from": previous, "to": patch["assignee_user_id"]},
                )
                updated_total += 1

    request_home_views_refresh()
    return {"ok": True, "updated": updated_total}
