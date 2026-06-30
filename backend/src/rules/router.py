"""REST endpoints for the Rules engine."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError

from src.rules import store
from src.rules.action_schemas import validate_action_for_category
from src.rules.schemas import (
    DryRunConfirmation,
    KillSwitchList,
    KillSwitchRead,
    KillSwitchRequest,
    RuleCreate,
    RuleList,
    RulePreviewRequest,
    RuleRead,
    RuleReadResponse,
    RuleSummaryResponse,
    RuleUpdate,
    RuleViolationPageResponse,
    RuleViolationRead,
)
from src.audit_log.recorder import ActorInfo, RequestContext, get_recorder
from src.authz.enforcement import require_permission
from src.authz.enforcement.dependencies import Permission
from src.authz.enforcement.scope import resolve_asset_ids_from_request
from src.authz.permissions.catalog import MANAGE_PERMISSION_BY_RULE_CATEGORY, VIEW_RULES
from src.authz.teams.access import actor_global_role, actor_user_id


VIOLATIONS_MAX_LIMIT = 200
VIOLATIONS_DEFAULT_LIMIT = 50


_DRY_RUN_TOKEN_TTL = timedelta(hours=1)


def _ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _resolve_user_identity(request: Request) -> str:
    user = (
        getattr(request.state, "user_id", None)
        or getattr(request.state, "user_email", None)
    )
    if not user:
        raise HTTPException(status_code=401, detail="missing user identity on request")
    return user


def _record_rule_audit(
    request: Request,
    *,
    action: str,
    resource_id: str | None,
    resource_type: str = "rule",
    metadata: dict | None = None,
) -> None:
    """Record an audit event for a rules-engine mutation.

    /api/v1/rules is not covered by the global audit middleware, so rule changes
    — which drive auto-dismiss / auto-archive of findings — must record their own
    events to stay in the compliance trail.
    """
    get_recorder().record(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor=ActorInfo(
            user_id=actor_user_id(request) or None,
            role=actor_global_role(request),
        ),
        request=RequestContext(
            method=request.method.upper(),
            path=request.url.path,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        ),
        metadata=metadata,
    )

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


def _manage_permission_for(category: str) -> str:
    try:
        return MANAGE_PERMISSION_BY_RULE_CATEGORY[category]
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"unknown category: {category!r}") from exc


@router.get(
    "",
    response_model=RuleList,
    summary="List rules with optional filters",
)
def list_rules_handler(
    request: Request,
    category: str | None = None,
    enabled: bool | None = None,
    q: str | None = None,
    _: None = Depends(Permission(VIEW_RULES)),
) -> RuleList:
    rows = store.list_rules(category=category, enabled=enabled, q=q)
    return RuleList(rules=[RuleRead.model_validate(r) for r in rows])


@router.get(
    "/summary",
    response_model=RuleSummaryResponse,
    summary="Rule summary KPI counts",
)
def get_rule_summary_handler(
    request: Request,
    _: None = Depends(Permission(VIEW_RULES)),
) -> RuleSummaryResponse:
    return RuleSummaryResponse.model_validate(store.summary())


@router.get(
    "/kill-switches",
    response_model=KillSwitchList,
    summary="List engaged kill switches",
)
def list_kill_switches_handler(
    request: Request,
    _: None = Depends(Permission(VIEW_RULES)),
) -> KillSwitchList:
    rows = store.list_kill_switches()
    return KillSwitchList(kill_switches=[KillSwitchRead.model_validate(r) for r in rows])


@router.get(
    "/{rule_id}",
    response_model=RuleReadResponse,
    summary="Get a single rule by id",
)
def get_rule_handler(
    request: Request,
    rule_id: str,
    _: None = Depends(Permission(VIEW_RULES)),
) -> RuleReadResponse:
    row = store.get_rule_by_id(rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return RuleReadResponse(rule=RuleRead.model_validate(row))


@router.get(
    "/{rule_id}/violations",
    response_model=RuleViolationPageResponse,
    summary="List violations for a rule (paginated)",
)
def list_rule_violations_handler(
    request: Request,
    rule_id: str,
    limit: int = VIOLATIONS_DEFAULT_LIMIT,
    offset: int = 0,
    _: None = Depends(Permission(VIEW_RULES)),
) -> RuleViolationPageResponse:
    clamped_limit = max(1, min(limit, VIOLATIONS_MAX_LIMIT))
    clamped_offset = max(0, offset)
    page = store.list_violations_for_rule(
        rule_id, limit=clamped_limit, offset=clamped_offset,
    )
    return RuleViolationPageResponse(
        violations=[RuleViolationRead.model_validate(v) for v in page["violations"]],
        total=page["total"],
        limit=page["limit"],
        offset=page["offset"],
    )


@router.post("/kill-switch/{category}", status_code=201)
def engage_kill_switch(
    request: Request, category: str, body: KillSwitchRequest
) -> dict:
    require_permission(request, _manage_permission_for(category))
    killed_by = _resolve_user_identity(request)
    try:
        row = store.engage_kill_switch(
            category=category,
            killed_by=killed_by,
            reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _record_rule_audit(
        request,
        action="rule.kill_switch.engaged",
        resource_type="rule_kill_switch",
        resource_id=category,
        metadata={"reason": body.reason},
    )
    return row


@router.delete("/kill-switch/{category}", status_code=204)
def disengage_kill_switch(request: Request, category: str) -> None:
    require_permission(request, _manage_permission_for(category))
    removed = store.disengage_kill_switch(category=category)
    if not removed:
        raise HTTPException(
            status_code=404, detail=f"no kill switch engaged for {category}"
        )
    _record_rule_audit(
        request,
        action="rule.kill_switch.disengaged",
        resource_type="rule_kill_switch",
        resource_id=category,
    )


@router.post("", status_code=201)
def create_rule(request: Request, body: RuleCreate) -> dict:
    require_permission(request, _manage_permission_for(body.category))
    try:
        validate_action_for_category(body.category, body.action)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if body.category == "auto_dismiss" and body.enabled is True:
        raise HTTPException(
            status_code=400,
            detail="auto_dismiss rules must be created disabled — enable via PUT after a dry-run confirmation",
        )

    created_by = _resolve_user_identity(request)
    rule = store.create_rule(
        category=body.category,
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        priority=body.priority,
        conditions=body.conditions,
        action=body.action,
        created_by=created_by,
    )
    _record_rule_audit(
        request,
        action="rule.created",
        resource_id=str(rule.get("id")) if rule.get("id") is not None else None,
        metadata={
            "category": body.category,
            "name": body.name,
            "enabled": body.enabled,
            "priority": body.priority,
        },
    )
    return {"rule": rule}


@router.put("/{rule_id}")
def update_rule(
    request: Request, rule_id: str, body: RuleUpdate
) -> dict:
    # The category-specific manage permission below is the authoritative
    # write gate. A separate VIEW_RULES check at the entry would be
    # redundant — and worse, it reads at a glance like the write only
    # needs view_rules, inviting a future refactor that accidentally
    # drops the real manage check and opens the write to any viewer.
    existing = store.get_rule_by_id(rule_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="rule not found")
    require_permission(request, _manage_permission_for(existing["category"]))

    update_kwargs = body.model_dump(exclude_unset=True)
    submitted_token = update_kwargs.pop("dry_run_confirmation_token", None)

    if "action" in update_kwargs:
        try:
            validate_action_for_category(existing["category"], update_kwargs["action"])
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.errors()) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    is_enable_transition = (
        existing["category"] == "auto_dismiss"
        and update_kwargs.get("enabled") is True
        and existing.get("enabled") is False
    )
    if is_enable_transition:
        _enforce_dry_run_gate(rule_id=rule_id, submitted_token=submitted_token)
        update_kwargs["dry_run_confirmation_token"] = None
        update_kwargs["dry_run_confirmed_at"] = datetime.now(timezone.utc)

    rule = store.update_rule(rule_id, **update_kwargs)
    _record_rule_audit(
        request,
        action="rule.updated",
        resource_id=rule_id,
        metadata={
            "category": existing["category"],
            "fields": sorted(update_kwargs.keys()),
        },
    )
    return {"rule": rule}


def _enforce_dry_run_gate(*, rule_id: str, submitted_token: str | None) -> None:
    if not submitted_token:
        raise HTTPException(
            status_code=400,
            detail="dry-run confirmation token required to enable an auto_dismiss rule",
        )
    record = store.get_dry_run_state(rule_id=rule_id)
    if record is None or record.get("token") is None:
        raise HTTPException(
            status_code=400,
            detail="no pending dry-run for this rule; run dry-run-and-confirm first",
        )
    if record["token"] != submitted_token:
        raise HTTPException(
            status_code=400,
            detail="dry-run confirmation token does not match",
        )
    last_run = record.get("last_dry_run_at")
    if last_run is None:
        raise HTTPException(
            status_code=400,
            detail="no pending dry-run for this rule; run dry-run-and-confirm first",
        )
    age = datetime.now(timezone.utc) - _ensure_aware(last_run)
    if age > _DRY_RUN_TOKEN_TTL:
        raise HTTPException(
            status_code=400,
            detail="dry-run confirmation token has expired; run dry-run-and-confirm again",
        )


@router.delete("/{rule_id}", status_code=204)
def delete_rule(request: Request, rule_id: str) -> None:
    existing = store.get_rule_by_id(rule_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="rule not found")
    require_permission(request, _manage_permission_for(existing["category"]))
    store.delete_rule(rule_id)
    _record_rule_audit(
        request,
        action="rule.deleted",
        resource_id=rule_id,
        metadata={"category": existing["category"], "name": existing.get("name")},
    )


@router.post("/{rule_id}/toggle")
def toggle_rule(request: Request, rule_id: str) -> dict:
    existing = store.get_rule_by_id(rule_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="rule not found")
    require_permission(request, _manage_permission_for(existing["category"]))
    if existing["category"] == "auto_dismiss" and existing.get("enabled") is False:
        raise HTTPException(
            status_code=400,
            detail="auto_dismiss rules cannot be enabled via toggle — use PUT /rules/{rule_id} with a dry-run confirmation token",
        )
    rule = store.toggle_rule(rule_id)
    _record_rule_audit(
        request,
        action="rule.toggled",
        resource_id=rule_id,
        metadata={"category": existing["category"], "enabled": rule.get("enabled")},
    )
    return {"rule": rule}


@router.post("/{rule_id}/preview")
def preview_rule(
    request: Request,
    rule_id: str,
    body: RulePreviewRequest,
    _: None = Depends(Permission(VIEW_RULES)),
) -> dict:
    rule = store.get_rule_by_id(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return {
        "matched_count": 0,
        "rule_id": rule_id,
        "category": rule["category"],
    }


@router.post("/{rule_id}/dry-run-and-confirm", response_model=DryRunConfirmation)
async def dry_run_and_confirm(
    request: Request, rule_id: str
) -> DryRunConfirmation:
    existing = store.get_rule_by_id(rule_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="rule not found")
    if existing["category"] != "auto_dismiss":
        raise HTTPException(
            status_code=400,
            detail="dry-run-and-confirm is only available for auto_dismiss rules",
        )
    require_permission(request, _manage_permission_for(existing["category"]))

    asset_ids = await resolve_asset_ids_from_request(request)
    try:
        match_count, sample_matches, token = store.preview_auto_dismiss_dry_run(
            rule_id=rule_id, asset_ids=asset_ids
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    now = datetime.now(timezone.utc)
    return DryRunConfirmation(
        token=token,
        match_count=match_count,
        sample_matches=sample_matches,
        valid_until=now + _DRY_RUN_TOKEN_TTL,
    )
