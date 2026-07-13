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

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select

from src.db.engine import get_session
from src.db.models import Asset, Finding, FindingEvent, User
from src.findings.service import (
    FIXED_WINDOW_DAYS,
    _finding_to_dict,
    advisory_intel,
    assign_finding,
    base_image_recommendation,
    count_related_repos,
    layer_concentration,
    list_related_findings,
    finding_advisory,
    list_assignable_users,
    summarize_findings,
)
from src.notifications.producers import notify_comment_mentions, notify_finding_assigned
from src.settings.audit_stream.service import record_event
from src.authz.enforcement import require_permission
from src.authz.enforcement.dependencies import Permission
from src.authz.teams.access import actor_user_id
from src.authz.permissions.catalog import (
    REVIEW_FINDINGS,
    RUN_SCANS,
    VIEW_FINDINGS,
)
from src.shared.lifecycle import (
    VALID_DISMISS_REASONS,
    bulk_dismiss_in_session,
    defer_finding,
    dismiss_finding,
    reopen_finding,
)
from src.shared.home_views_refresher import request_home_views_refresh
from src.exports.pdf import render_pdf
from src.findings.advisory import (
    compose_advisory_html,
    compose_advisory_markdown,
    poc_artifact,
)
from src.findings.poc_generation import PocGenerationError, generate_poc
from src.settings.llm.router import _resolve_org_id
from src.settings.llm.service import fetch_llm_config
from src.authz.enforcement.scope import assignable_user_ids, resolve_asset_ids_from_request

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

_VALID_STATE_TRANSITIONS = frozenset({"dismissed", "open", "deferred"})
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
    """Return active users matching `q` for finding-assignee pickers.

    Scoped to co-assignees the caller shares an asset with, so the picker
    never enumerates the full user directory.
    """
    ctx = {
        "user_id": request.state.user_sub,
        "role": getattr(request.state, "user_role", "viewer"),
    }
    async with get_session() as session:
        allowed = await assignable_user_ids(session, ctx)
        users = await list_assignable_users(
            session, q=q, limit=limit, allowed_user_ids=allowed
        )
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
        result = await session.execute(
            select(Finding).where(Finding.id == finding_id, Finding.asset_id.in_(asset_ids))
        )
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
    elif patch.get("state") == "deferred":
        defer_finding(
            finding.tool, finding.identity_key, user_id, asset_id=finding.asset_id,
        )
        record_event(
            action="finding.deferred",
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
                await notify_finding_assigned(
                    session,
                    finding=updated,
                    assignee_user_id=payload["assignee_user_id"],
                    previous_assignee=previous,
                    actor_user_id=user_id,
                )
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



_MAX_COMMENT_LEN = 5000


async def _usernames_for(session, ids: set[str]) -> dict[str, str]:
    """Map user ids → usernames so comments show a name, not the raw id."""
    ids = {i for i in ids if i}
    if not ids:
        return {}
    result = await session.execute(
        select(User.id, User.username).where(User.id.in_(ids))
    )
    return {row[0]: row[1] for row in result.all()}


def _serialise_comment(event: FindingEvent, names: dict[str, str]) -> dict[str, Any]:
    return {
        "id": str(event.id),
        # Display the username; fall back to the id for deleted/unknown users.
        "actor": names.get(event.actor or "", event.actor),
        "body": (event.metadata_json or {}).get("comment", ""),
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }


async def _load_scoped_finding(finding_id: int, request: Request) -> Finding:
    """Fetch a finding only if it's within the caller's asset scope, else 404."""
    asset_ids = await resolve_asset_ids_from_request(request)
    scope = set(asset_ids)
    async with get_session() as session:
        # Scope at the SQL layer so out-of-scope rows never leave Postgres; the
        # Python check below is the backstop, mirroring the bulk-PATCH path.
        result = await session.execute(
            select(Finding).where(Finding.id == finding_id, Finding.asset_id.in_(asset_ids))
        )
        finding = result.scalars().first()
    if finding is None or not finding.asset_id or finding.asset_id not in scope:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get("/{finding_id}/comments")
async def list_finding_comments(finding_id: int, request: Request) -> dict[str, Any]:
    """List the comments on a finding, oldest first."""
    require_permission(request, REVIEW_FINDINGS)
    await _load_scoped_finding(finding_id, request)
    async with get_session() as session:
        result = await session.execute(
            select(FindingEvent)
            .where(FindingEvent.finding_id == finding_id, FindingEvent.to_state == "comment")
            .order_by(FindingEvent.created_at)
        )
        events = result.scalars().all()
        names = await _usernames_for(session, {e.actor for e in events if e.actor})
    return {"comments": [_serialise_comment(e, names) for e in events]}


@router.post("/{finding_id}/comments")
async def add_finding_comment(finding_id: int, request: Request) -> dict[str, Any]:
    """Add a free-text comment to a finding (stored on its activity timeline)."""
    require_permission(request, REVIEW_FINDINGS)
    body = await request.json()
    text = body.get("comment")
    if not isinstance(text, str) or not text.strip():
        raise HTTPException(status_code=400, detail="comment is required")
    text = text.strip()
    if len(text) > _MAX_COMMENT_LEN:
        raise HTTPException(status_code=400, detail=f"comment must be <= {_MAX_COMMENT_LEN} chars")

    finding = await _load_scoped_finding(finding_id, request)
    user_id = actor_user_id(request) or "unknown"
    async with get_session() as session:
        event = FindingEvent(
            finding_id=finding.id,
            from_state=None,
            to_state="comment",
            triggered_by="user",
            actor=user_id,
            metadata_json={"comment": text},
        )
        session.add(event)
        await notify_comment_mentions(
            session,
            finding=finding,
            comment_text=text,
            actor_user_id=user_id,
        )
        await session.commit()
        await session.refresh(event)
        names = await _usernames_for(session, {user_id})
        serialised = _serialise_comment(event, names)

    record_event(
        action="finding.commented",
        actor_user_id=user_id,
        target=str(finding_id),
        metadata={"tool": finding.tool, "length": len(text)},
    )
    return {"comment": serialised}


@router.get("/{finding_id}")
async def get_finding_detail(finding_id: int, request: Request) -> dict[str, Any]:
    """Full detail for one finding.

    The list view comes from GraphQL with a lean row; the panel fetches this on
    open to get the decision content (description, rule, remediation, confidence,
    code snippet + highlight) that `_finding_to_dict` computes but the list omits.
    """
    require_permission(request, VIEW_FINDINGS)
    finding = await _load_scoped_finding(finding_id, request)
    # Blast radius: other in-scope assets sharing this CVE/package.
    asset_ids = await resolve_asset_ids_from_request(request)
    async with get_session() as session:
        # Resolve the repo ref (Asset.display_name, e.g. "github:acme/api") so the
        # detail carries the provider prefix — the list path does this too, and
        # without it the view-in-repo deep-link loses its file+line anchor.
        repo = None
        if finding.asset_id:
            repo = await session.scalar(
                select(Asset.display_name).where(Asset.id == finding.asset_id)
            )
        # hydrate=True: the drawer needs the code window / snippet / code flows /
        # manifest snippet, which live in the fat blob, not the lean list row.
        data = _finding_to_dict(finding, repo=repo, hydrate=True)
        data["also_affects_repos"] = await count_related_repos(finding, asset_ids, session)
        img = data.get("container_image")
        if isinstance(img, dict):
            img["layer_concentration"] = await layer_concentration(finding, session)
            img["base_image_recommendation"] = await base_image_recommendation(
                img.get("digest"), session
            )
    return {"finding": data}


@router.get("/{finding_id}/advisory")
async def get_finding_advisory(finding_id: int, request: Request) -> dict[str, Any]:
    """Advisory enrichment for the drawer's Security Brief: summary, severity +
    CVSS, the affected → patched range, references, plus EPSS/KEV intel.

    Lazily hydrated from the finding's detail blob on drawer open. Returns
    ``{"advisory": null}`` for findings with no advisory (SAST / secrets / IaC);
    an out-of-scope id 404s via the scoped load.
    """
    require_permission(request, VIEW_FINDINGS)
    finding = await _load_scoped_finding(finding_id, request)
    advisory = finding_advisory(finding)
    if advisory and advisory.get("cve_id"):
        async with get_session() as session:
            advisory.update(await advisory_intel(advisory["cve_id"], session))
    return {"advisory": advisory}


@router.get("/{finding_id}/related")
async def get_finding_related(finding_id: int, request: Request) -> dict[str, Any]:
    """Blast-radius drill-down: other in-scope repos with an active finding for
    this finding's CVE/package, one row per repo, worst-severity first."""
    require_permission(request, VIEW_FINDINGS)
    finding = await _load_scoped_finding(finding_id, request)
    asset_ids = await resolve_asset_ids_from_request(request)
    async with get_session() as session:
        related = await list_related_findings(finding, asset_ids, session)
    return {"related": related}


def _safe_slug(finding: dict[str, Any]) -> str:
    """Filesystem-safe stem for the report filename."""
    raw = (finding.get("title") or f"finding-{finding.get('id', 'x')}").lower()
    slug = "".join(c if c.isalnum() else "-" for c in raw).strip("-")
    return (slug or "finding")[:60]


async def _scoped_finding_dict(finding_id: int, request: Request) -> dict[str, Any]:
    """Load a scoped finding and hydrate it to the same dict the detail route
    returns. 404s out of scope via _load_scoped_finding."""
    finding = await _load_scoped_finding(finding_id, request)
    repo = None
    if finding.asset_id:
        async with get_session() as session:
            repo = await session.scalar(
                select(Asset.display_name).where(Asset.id == finding.asset_id)
            )
    return _finding_to_dict(finding, repo=repo, hydrate=True)


@router.get("/{finding_id}/report.md")
async def download_finding_report(finding_id: int, request: Request) -> Response:
    """Download the finding as a security-advisory Markdown document. Out-of-scope
    or unknown ids 404 via the scoped load (no id enumeration)."""
    require_permission(request, VIEW_FINDINGS)
    finding = await _scoped_finding_dict(finding_id, request)
    markdown = compose_advisory_markdown(finding)
    return Response(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_safe_slug(finding)}.md"'},
    )


@router.get("/{finding_id}/report.pdf")
async def download_finding_report_pdf(finding_id: int, request: Request) -> Response:
    """Download the finding advisory as a PDF. Same scope gating as the Markdown
    report; out-of-scope or unknown ids 404 via the scoped load."""
    require_permission(request, VIEW_FINDINGS)
    finding = await _scoped_finding_dict(finding_id, request)
    pdf = render_pdf(compose_advisory_html(finding))
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{_safe_slug(finding)}.pdf"'},
    )


@router.get("/{finding_id}/poc")
async def download_finding_poc(finding_id: int, request: Request) -> Response:
    """Download the finding's runnable benign PoC script (safe-harbor header
    prepended). 404 when the finding has no PoC."""
    require_permission(request, VIEW_FINDINGS)
    finding = await _scoped_finding_dict(finding_id, request)
    artifact = poc_artifact(finding)
    if artifact is None:
        raise HTTPException(status_code=404, detail="No proof-of-concept for this finding")
    filename, body = artifact
    return Response(
        content=body,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


async def _persist_finding_poc(finding_id: int, poc: dict[str, str]) -> None:
    """Merge a generated PoC into the finding's verification_metadata so the
    download route and subsequent drawer opens serve it without regenerating."""
    async with get_session() as session:
        finding = await session.get(Finding, finding_id)
        if finding is None:
            return
        meta = dict(finding.verification_metadata or {})
        meta["poc_script"] = poc["poc_script"]
        if poc.get("poc_filename"):
            meta["poc_filename"] = poc["poc_filename"]
        if poc.get("poc_language"):
            meta["poc_language"] = poc["poc_language"]
        finding.verification_metadata = meta
        await session.commit()


@router.post("/{finding_id}/poc/generate")
async def generate_finding_poc(finding_id: int, request: Request) -> dict[str, Any]:
    """Generate a benign PoC for a finding on demand. Gated by run_scans because
    it spends LLM tokens; scoped like the other finding reads (404 out of scope).
    The result is persisted so the download route serves it afterwards."""
    require_permission(request, RUN_SCANS)
    finding = await _scoped_finding_dict(finding_id, request)
    cfg = fetch_llm_config(_resolve_org_id())
    if cfg is None or not cfg.enabled or not cfg.api_key:
        raise HTTPException(status_code=409, detail="LLM is not configured")
    try:
        poc = await generate_poc(
            finding, api_key=cfg.api_key, base_url=cfg.api_base_url, model=cfg.model
        )
    except PocGenerationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    await _persist_finding_poc(finding_id, poc)
    return {"poc": poc}


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
                updated, previous = await assign_finding(
                    f.id, patch["assignee_user_id"], session, asset_ids,
                )
                await notify_finding_assigned(
                    session,
                    finding=updated,
                    assignee_user_id=patch["assignee_user_id"],
                    previous_assignee=previous,
                    actor_user_id=user_id,
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
