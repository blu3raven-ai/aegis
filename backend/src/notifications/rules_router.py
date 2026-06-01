"""REST endpoints for notification routing rules (Phase 42).

All endpoints require manage_settings permission, mirroring the pattern
used by admin_router.py for notification destinations.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.notifications.rules_model import (
    create_rule,
    delete_rule,
    get_rule,
    list_rules,
    update_rule,
)
from src.notifications.routing import Finding, Rule, evaluate_condition, route_finding
from src.settings.router import require_permission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/notification-rules", tags=["notification-rules"])


# ── Request / response schemas ────────────────────────────────────────────────


class CreateRuleRequest(BaseModel):
    org_id: str
    name: str = Field(..., max_length=120)
    channel_id: int
    conditions: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=100, ge=0)
    enabled: bool = True


class UpdateRuleRequest(BaseModel):
    name: str | None = Field(default=None, max_length=120)
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=0)
    channel_id: int | None = None
    conditions: dict[str, Any] | None = None


class PreviewFinding(BaseModel):
    severity: str = "medium"
    scanner: str = ""
    repo_id: str = ""
    repo_labels: list[str] = Field(default_factory=list)
    cve_id: str | None = None
    chain_role: str | None = None


class PreviewRequest(BaseModel):
    """Dry-run: evaluate a rule (or all org rules) against a sample finding."""
    rule: CreateRuleRequest | None = None          # single rule to preview
    org_id: str | None = None                      # if set, evaluate all active rules
    finding: PreviewFinding


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("")
def list_notification_rules(request: Request, org_id: str) -> dict:
    require_permission(request, "manage_settings")
    return {"rules": list_rules(org_id)}


@router.post("", status_code=201)
def create_notification_rule(request: Request, body: CreateRuleRequest) -> dict:
    require_permission(request, "manage_settings")
    try:
        rule = create_rule(
            org_id=body.org_id,
            name=body.name,
            channel_id=body.channel_id,
            conditions=body.conditions,
            priority=body.priority,
            enabled=body.enabled,
        )
    except Exception as exc:
        logger.exception("create_rule failed")
        raise HTTPException(status_code=500, detail="internal error") from exc
    return rule


@router.get("/{rule_id}")
def get_notification_rule(request: Request, rule_id: str, org_id: str) -> dict:
    require_permission(request, "manage_settings")
    rule = get_rule(rule_id, org_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return rule


@router.put("/{rule_id}")
def update_notification_rule(
    request: Request, rule_id: str, org_id: str, body: UpdateRuleRequest
) -> dict:
    require_permission(request, "manage_settings")
    rule = update_rule(
        rule_id,
        org_id,
        name=body.name,
        enabled=body.enabled,
        priority=body.priority,
        channel_id=body.channel_id,
        conditions=body.conditions,
    )
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return rule


@router.delete("/{rule_id}", status_code=204)
def delete_notification_rule(request: Request, rule_id: str, org_id: str) -> None:
    require_permission(request, "manage_settings")
    deleted = delete_rule(rule_id, org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="rule not found")


@router.post("/preview")
def preview_rule_match(request: Request, body: PreviewRequest) -> dict:
    """Dry-run endpoint: evaluate a rule or full rule list against a sample finding.

    If body.rule is set, evaluates only that rule's conditions.
    If body.org_id is set, loads all active rules and returns which one matches.
    Returns the matched channel_id(s) and per-rule match details.
    """
    require_permission(request, "manage_settings")

    finding = Finding(
        severity=body.finding.severity,
        scanner=body.finding.scanner,
        repo_id=body.finding.repo_id,
        repo_labels=body.finding.repo_labels,
        cve_id=body.finding.cve_id,
        chain_role=body.finding.chain_role,
    )

    if body.rule is not None:
        # Single-rule preview — don't touch the DB
        try:
            matched = evaluate_condition(body.rule.conditions, finding)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "matched": matched,
            "channel_id": body.rule.channel_id if matched else None,
            "rule_name": body.rule.name,
        }

    if body.org_id is not None:
        from src.notifications.rules_model import get_active_rules_for_org

        rules = get_active_rules_for_org(body.org_id)
        channel_ids = route_finding(finding, rules)
        # Build per-rule breakdown for the UI
        breakdown = []
        for rule in rules:
            try:
                match = evaluate_condition(rule.conditions, finding)
            except Exception:
                match = False
            breakdown.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "priority": rule.priority,
                "channel_id": rule.channel_id,
                "matched": match,
            })
        return {
            "matched_channel_ids": channel_ids,
            "breakdown": breakdown,
        }

    raise HTTPException(
        status_code=422,
        detail="provide either 'rule' for single-rule preview or 'org_id' for full evaluation",
    )
