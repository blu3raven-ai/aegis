"""Notification configuration: destination channels and routing rules."""
from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from src.audit_log.decorators import audited
from src.notifications.destination import (
    VALID_DEST_TYPES,
    create_destination,
    delete_destination,
    get_destination,
    redact_config,
    update_destination,
)
from src.notifications.rules_model import (
    create_rule,
    delete_rule,
    get_rule,
    update_rule,
)
from src.notifications.routing import Finding, evaluate_condition, route_finding
from src.notifications.test_send import build_test_payload, send_test_payload
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS

logger = logging.getLogger(__name__)


# === Destinations sub-router ================================================

_destinations = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])


class CreateDestinationRequest(BaseModel):
    destination_type: str
    name: str
    config: dict[str, Any]
    enabled: bool = True
    event_filter: dict[str, Any] | None = None


class UpdateDestinationRequest(BaseModel):
    name: str | None = None
    config: dict[str, Any] | None = None
    enabled: bool | None = None
    event_filter: dict[str, Any] | None = None


@_destinations.get("/destinations/{dest_id}")
def get_notification_destination(
    request: Request,
    dest_id: int,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    dest = get_destination(dest_id)
    if dest is None:
        raise HTTPException(status_code=404, detail="destination not found")
    return {**dest, "config": redact_config(dest.get("config"))}


@_destinations.post("/destinations", status_code=201)
@audited(action="notification.destination.created", resource_type="notification_destination")
def create_notification_destination(
    request: Request,
    body: CreateDestinationRequest,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    if body.destination_type not in VALID_DEST_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"destination_type must be one of {sorted(VALID_DEST_TYPES)}",
        )

    try:
        dest = create_destination(
            destination_type=body.destination_type,
            name=body.name,
            config=body.config,
            enabled=body.enabled,
            event_filter=body.event_filter,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        if "uq_notif_dest_name" in str(exc):
            raise HTTPException(
                status_code=409, detail="a destination with that name already exists"
            ) from exc
        logger.exception("create_destination failed")
        raise HTTPException(status_code=500, detail="internal error") from exc

    return {**dest, "config": redact_config(dest.get("config"))}


@_destinations.put("/destinations/{dest_id}")
@audited(action="notification.destination.updated", resource_type="notification_destination", resource_id_param="dest_id")
def update_notification_destination(
    request: Request,
    dest_id: int,
    body: UpdateDestinationRequest,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    dest = update_destination(
        dest_id,
        name=body.name,
        config=body.config,
        enabled=body.enabled,
        event_filter=body.event_filter,
    )
    if dest is None:
        raise HTTPException(status_code=404, detail="destination not found")
    return {**dest, "config": redact_config(dest.get("config"))}


@_destinations.delete("/destinations/{dest_id}", status_code=204)
@audited(action="notification.destination.deleted", resource_type="notification_destination", resource_id_param="dest_id")
def delete_notification_destination(
    request: Request,
    dest_id: int,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> None:
    deleted = delete_destination(dest_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="destination not found")



@_destinations.post("/destinations/{dest_id}/test")
@audited(
    action="notification.destination.test_sent",
    resource_type="notification_destination",
    resource_id_param="dest_id",
)
def test_send_destination(
    request: Request,
    dest_id: int,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    """Send a canned test payload through the destination's channel."""
    dest = get_destination(dest_id)
    if dest is None:
        raise HTTPException(status_code=404, detail="destination not found")

    dtype = dest.get("destination_type", "")
    if dtype not in VALID_DEST_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"unsupported destination channel: {dtype}",
        )
    payload = build_test_payload(dtype, dest.get("name", ""))

    start = time.monotonic()
    result = send_test_payload(dtype, payload, dest.get("config") or {})
    latency_ms = int((time.monotonic() - start) * 1000)

    if result.success:
        return {
            "status": "delivered",
            "channel": dtype,
            "latency_ms": latency_ms,
        }
    return {
        "status": "failed",
        "channel": dtype,
        "error": result.error or "delivery failed",
        "latency_ms": latency_ms,
    }


# === Rules sub-router =======================================================

_rules = APIRouter(prefix="/api/v1/notifications/rules", tags=["notifications"])


class CreateRuleRequest(BaseModel):
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
    """Dry-run: evaluate a rule (or all active rules) against a sample finding."""
    rule: CreateRuleRequest | None = None              # single rule to preview
    evaluate_all_active: bool = False                  # if true, evaluate all active rules
    finding: PreviewFinding


@_rules.post("", status_code=201)
def create_notification_rule(
    request: Request,
    body: CreateRuleRequest,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    try:
        rule = create_rule(
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


@_rules.get("/{rule_id}")
def get_notification_rule(
    request: Request,
    rule_id: str,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    rule = get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return rule


@_rules.put("/{rule_id}")
def update_notification_rule(
    request: Request,
    rule_id: str,
    body: UpdateRuleRequest,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    rule = update_rule(
        rule_id,
        name=body.name,
        enabled=body.enabled,
        priority=body.priority,
        channel_id=body.channel_id,
        conditions=body.conditions,
    )
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return rule


@_rules.delete("/{rule_id}", status_code=204)
def delete_notification_rule(
    request: Request,
    rule_id: str,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> None:
    deleted = delete_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="rule not found")


@_rules.post("/preview")
def preview_rule_match(
    request: Request,
    body: PreviewRequest,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    """Dry-run endpoint: evaluate a rule or the full active rule list."""
    finding = Finding(
        severity=body.finding.severity,
        scanner=body.finding.scanner,
        repo_id=body.finding.repo_id,
        repo_labels=body.finding.repo_labels,
        cve_id=body.finding.cve_id,
        chain_role=body.finding.chain_role,
    )

    if body.rule is not None:
        try:
            matched = evaluate_condition(body.rule.conditions, finding)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "matched": matched,
            "channel_id": body.rule.channel_id if matched else None,
            "rule_name": body.rule.name,
        }

    if body.evaluate_all_active:
        from src.notifications.rules_model import get_active_rules

        rules = get_active_rules()
        channel_ids = route_finding(finding, rules)
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
        detail="provide either 'rule' for single-rule preview or set evaluate_all_active=true",
    )


# === Exported combined router ===============================================

config_router = APIRouter()
config_router.include_router(_destinations)
config_router.include_router(_rules)
