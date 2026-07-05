"""Pydantic schemas for the Rules CRUD API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


RuleCategory = Literal["sla", "scanner_coverage", "auto_dismiss", "data_retention"]


class RuleCreate(BaseModel):
    category: RuleCategory
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    enabled: bool = True
    priority: int = Field(default=100, ge=0)
    conditions: dict[str, Any] = Field(default_factory=dict)
    action: dict[str, Any] = Field(default_factory=dict)


class RuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=0)
    conditions: dict[str, Any] | None = None
    action: dict[str, Any] | None = None
    dry_run_confirmation_token: str | None = None


class RulePreviewRequest(BaseModel):
    """Dry-run: count subjects in the org that would match the rule's conditions."""
    sample_subject: dict[str, Any] | None = None


class KillSwitchRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class DryRunSampleMatch(BaseModel):
    finding_id: int
    severity: str
    scanner: str
    repo_id: str
    file_path: str | None = None
    cve_id: str | None = None


class DryRunConfirmation(BaseModel):
    token: str
    match_count: int
    sample_matches: list[DryRunSampleMatch]
    valid_until: datetime


# Read envelopes for the GET endpoints. Snake_case fields on the wire — the
# TS client already destructures snake_case so no adapter layer is needed.


class RuleRead(BaseModel):
    id: str
    category: str
    name: str
    description: str | None = None
    enabled: bool
    priority: int
    conditions: dict[str, Any] = Field(default_factory=dict)
    action: dict[str, Any] = Field(default_factory=dict)
    created_by: str
    created_at: str
    updated_at: str | None = None
    last_evaluated_at: str | None = None
    violation_count_open: int = 0
    violation_count_resolved_30d: int = 0


class RuleList(BaseModel):
    rules: list[RuleRead]


class RuleReadResponse(BaseModel):
    rule: RuleRead


class RuleSummaryResponse(BaseModel):
    active_rules: int
    violations_open: int
    coverage_gaps: int
    sla_compliance_pct: float


class RuleViolationRead(BaseModel):
    id: int
    rule_id: str
    subject_type: str
    subject_id: str
    status: str
    opened_at: str
    resolved_at: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class RuleViolationPageResponse(BaseModel):
    violations: list[RuleViolationRead]
    total: int
    limit: int
    offset: int


class KillSwitchRead(BaseModel):
    id: int
    category: str
    killed_at: str
    killed_by: str
    reason: str | None = None


class KillSwitchList(BaseModel):
    kill_switches: list[KillSwitchRead]
