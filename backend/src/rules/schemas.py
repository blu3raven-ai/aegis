"""Pydantic schemas for the Rules CRUD API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


RuleCategory = Literal["sla", "scanner_coverage", "auto_dismiss", "data_retention"]


class RuleCreate(BaseModel):
    org_id: str
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
