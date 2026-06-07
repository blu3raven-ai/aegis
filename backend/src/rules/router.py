"""REST endpoints for the unified Rules engine (P1 — SLA category only).

Other categories (scanner_coverage, auto_dismiss, data_retention) are
recognised by the router but rejected at action-schema validation until
their phase ships.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError

from src.rules import store
from src.rules.action_schemas import validate_action_for_category
from src.rules.schemas import (
    DryRunConfirmation,
    KillSwitchRequest,
    RuleCreate,
    RulePreviewRequest,
    RuleUpdate,
)
from src.settings.router import require_permission


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

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


_MANAGE_PERMISSION_BY_CATEGORY = {
    "sla": "manage_sla_rules",
    "scanner_coverage": "manage_scanner_coverage_rules",
    "auto_dismiss": "manage_auto_dismiss_rules",
    "data_retention": "manage_data_retention_rules",
}


def _manage_permission_for(category: str) -> str:
    try:
        return _MANAGE_PERMISSION_BY_CATEGORY[category]
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"unknown category: {category!r}") from exc


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("")
def list_rules(
    request: Request,
    org_id: str,
    category: str | None = None,
    enabled: bool | None = None,
    q: str | None = None,
) -> dict:
    require_permission(request, "view_rules")
    return {
        "rules": store.list_rules_for_org(
            org_id, category=category, enabled=enabled, q=q
        )
    }


@router.get("/summary")
def get_summary(request: Request, org_id: str) -> dict:
    require_permission(request, "view_rules")
    return {"summary": store.summary_for_org(org_id)}


# ── Kill switch ──────────────────────────────────────────────────────────────
# Declared before any /{rule_id} route so FastAPI's first-match routing doesn't
# treat "kill-switch" as a rule id.


@router.get("/kill-switch")
def list_kill_switches(request: Request, org_id: str) -> dict:
    require_permission(request, "view_rules")
    return {"kill_switches": store.list_kill_switches(org_id=org_id)}


@router.post("/kill-switch/{category}", status_code=201)
def engage_kill_switch(
    request: Request, category: str, body: KillSwitchRequest, org_id: str
) -> dict:
    require_permission(request, _manage_permission_for(category))
    killed_by = _resolve_user_identity(request)
    try:
        row = store.engage_kill_switch(
            org_id=org_id,
            category=category,
            killed_by=killed_by,
            reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return row


@router.delete("/kill-switch/{category}", status_code=204)
def disengage_kill_switch(request: Request, category: str, org_id: str) -> None:
    require_permission(request, _manage_permission_for(category))
    removed = store.disengage_kill_switch(org_id=org_id, category=category)
    if not removed:
        raise HTTPException(
            status_code=404, detail=f"no kill switch engaged for {category}"
        )


@router.get("/{rule_id}")
def get_rule(request: Request, rule_id: str, org_id: str) -> dict:
    require_permission(request, "view_rules")
    rule = store.get_rule_by_id(org_id, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return {"rule": rule}


@router.get("/{rule_id}/violations")
def list_violations(
    request: Request,
    rule_id: str,
    org_id: str,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    require_permission(request, "view_rules")
    rule = store.get_rule_by_id(org_id, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return store.list_violations_for_rule(org_id, rule_id, limit=limit, offset=offset)


@router.post("", status_code=201)
def create_rule(request: Request, body: RuleCreate) -> dict:
    require_permission(request, _manage_permission_for(body.category))
    try:
        validate_action_for_category(body.category, body.action)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # auto_dismiss rules must be created disabled and enabled only after a
    # dry-run confirmation (PUT with a valid token).
    if body.category == "auto_dismiss" and body.enabled is True:
        raise HTTPException(
            status_code=400,
            detail="auto_dismiss rules must be created disabled — enable via PUT after a dry-run confirmation",
        )

    created_by = _resolve_user_identity(request)
    rule = store.create_rule(
        org_id=body.org_id,
        category=body.category,
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        priority=body.priority,
        conditions=body.conditions,
        action=body.action,
        created_by=created_by,
    )
    return {"rule": rule}


@router.put("/{rule_id}")
def update_rule(
    request: Request, rule_id: str, body: RuleUpdate, org_id: str
) -> dict:
    require_permission(request, "view_rules")
    existing = store.get_rule_by_id(org_id, rule_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="rule not found")
    require_permission(request, _manage_permission_for(existing["category"]))

    update_kwargs = body.model_dump(exclude_unset=True)
    # Strip the gate token from the kwargs immediately — the router is the
    # only legitimate writer of dry_run_confirmation_token, and only as part
    # of a successful gate consumption (set to None below).
    submitted_token = update_kwargs.pop("dry_run_confirmation_token", None)

    if "action" in update_kwargs:
        try:
            validate_action_for_category(existing["category"], update_kwargs["action"])
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.errors()) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Dry-run gate: an auto_dismiss rule can only be flipped from disabled to
    # enabled when paired with a fresh, matching confirmation token. Any other
    # category or any other transition skips the gate entirely.
    is_enable_transition = (
        existing["category"] == "auto_dismiss"
        and update_kwargs.get("enabled") is True
        and existing.get("enabled") is False
    )
    if is_enable_transition:
        # why: keep raw token off the public dict; single extra SELECT on rare enable path
        _enforce_dry_run_gate(rule_id=rule_id, org_id=org_id, submitted_token=submitted_token)
        update_kwargs["dry_run_confirmation_token"] = None
        update_kwargs["dry_run_confirmed_at"] = datetime.now(timezone.utc)

    rule = store.update_rule(org_id, rule_id, **update_kwargs)
    return {"rule": rule}


def _enforce_dry_run_gate(*, rule_id: str, org_id: str, submitted_token: str | None) -> None:
    """Validate the P4 dry-run-and-confirm gate for an auto_dismiss enable.

    Four failure modes, each surfaced with a distinct 400 detail so callers
    can show targeted guidance.
    """
    if not submitted_token:
        raise HTTPException(
            status_code=400,
            detail="dry-run confirmation token required to enable an auto_dismiss rule",
        )
    record = store.get_dry_run_state(org_id=org_id, rule_id=rule_id)
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
def delete_rule(request: Request, rule_id: str, org_id: str) -> None:
    require_permission(request, "view_rules")
    existing = store.get_rule_by_id(org_id, rule_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="rule not found")
    require_permission(request, _manage_permission_for(existing["category"]))
    store.delete_rule(org_id, rule_id)


@router.post("/{rule_id}/toggle")
def toggle_rule(request: Request, rule_id: str, org_id: str) -> dict:
    require_permission(request, "view_rules")
    existing = store.get_rule_by_id(org_id, rule_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="rule not found")
    require_permission(request, _manage_permission_for(existing["category"]))
    # Toggling a disabled auto_dismiss rule to enabled must go through the
    # dry-run gate (PUT with a confirmation token). Disabling is always safe.
    if existing["category"] == "auto_dismiss" and existing.get("enabled") is False:
        raise HTTPException(
            status_code=400,
            detail="auto_dismiss rules cannot be enabled via toggle — use PUT /rules/{rule_id} with a dry-run confirmation token",
        )
    rule = store.toggle_rule(org_id, rule_id)
    return {"rule": rule}


@router.post("/{rule_id}/preview")
def preview_rule(
    request: Request, rule_id: str, body: RulePreviewRequest, org_id: str
) -> dict:
    """P1: returns a stub count. Real preview computation lands in P2."""
    require_permission(request, "view_rules")
    rule = store.get_rule_by_id(org_id, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return {
        "matched_count": 0,
        "rule_id": rule_id,
        "category": rule["category"],
    }


@router.post("/{rule_id}/dry-run-and-confirm", response_model=DryRunConfirmation)
def dry_run_and_confirm(
    request: Request, rule_id: str, org_id: str
) -> DryRunConfirmation:
    """P4 dry-run gate: compute matches, mint a single-use token, return both.

    Only auto_dismiss rules use this gate — other categories don't carry the
    enable-time guardrail and are rejected fast with 400.
    """
    require_permission(request, "view_rules")
    existing = store.get_rule_by_id(org_id, rule_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="rule not found")
    if existing["category"] != "auto_dismiss":
        raise HTTPException(
            status_code=400,
            detail="dry-run-and-confirm is only available for auto_dismiss rules",
        )
    require_permission(request, _manage_permission_for(existing["category"]))

    try:
        match_count, sample_matches, token = store.preview_auto_dismiss_dry_run(
            org_id=org_id, rule_id=rule_id
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
