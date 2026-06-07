"""Subject types for the unified Rules engine.

This module defines the three subject types that the unified Rules engine
operates on: findings, repos, and scan results. Each subject has a
corresponding getter that validates field names against an allowlist.

Field allowlists are intentionally narrow — adding a new predicate field
requires a code change so we can reason about the predicate vocabulary.

`datetime` fields on these subjects are expected to be timezone-aware (UTC),
since they are populated from `DateTime(timezone=True)` columns; mixing naive
and aware datetimes in the condition engine's ordinal operators raises `TypeError`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class RuleFindingSubject:
    """Subject for SLA and Auto-dismiss rules (operate per-finding)."""
    finding_id: int
    severity: str
    scanner: str
    repo_id: str
    repo_labels: list[str] = field(default_factory=list)
    repo_archived: bool = False
    cve_id: str | None = None
    cwe_id: str | None = None
    kev_matched: bool = False
    epss_score: float | None = None
    file_path: str | None = None
    age_days: int = 0  # since first_seen_at


@dataclass
class RuleRepoSubject:
    """Subject for Scanner-coverage rules (operate per-repo)."""
    repo_id: str
    repo_labels: list[str] = field(default_factory=list)
    tier: str | None = None  # 'production' | 'staging' | etc.
    archived: bool = False
    scanners_with_coverage: list[str] = field(default_factory=list)
    image_registry: str | None = None
    last_scanned_at: datetime | None = None
    last_scan_age_days: int | None = None


@dataclass
class RuleScanResultSubject:
    """Subject for Data-retention rules (operate per-scan-result)."""
    scan_id: str
    repo_id: str
    tool: str
    finished_at: datetime
    age_days: int


# `finding_id` is identity-only — intentionally excluded so rules cannot predicate on the PK.
_FINDING_FIELDS: frozenset[str] = frozenset({
    "severity", "scanner", "repo_id", "repo_labels", "repo_archived",
    "cve_id", "cwe_id", "kev_matched", "epss_score", "file_path", "age_days",
})

_REPO_FIELDS: frozenset[str] = frozenset({
    "repo_id", "repo_labels", "tier", "archived",
    "scanners_with_coverage", "image_registry", "last_scanned_at",
    "last_scan_age_days",
})

_SCAN_RESULT_FIELDS: frozenset[str] = frozenset({
    "scan_id", "repo_id", "tool", "finished_at", "age_days",
})


def get_finding_field(subject: RuleFindingSubject, name: str) -> Any:
    if name not in _FINDING_FIELDS:
        raise ValueError(f"unknown finding rule field: {name!r}")
    return getattr(subject, name)


def get_repo_field(subject: RuleRepoSubject, name: str) -> Any:
    if name not in _REPO_FIELDS:
        raise ValueError(f"unknown repo rule field: {name!r}")
    return getattr(subject, name)


def get_scan_result_field(subject: RuleScanResultSubject, name: str) -> Any:
    if name not in _SCAN_RESULT_FIELDS:
        raise ValueError(f"unknown scan-result rule field: {name!r}")
    return getattr(subject, name)


__all__ = [
    "RuleFindingSubject",
    "RuleRepoSubject",
    "RuleScanResultSubject",
    "get_finding_field",
    "get_repo_field",
    "get_scan_result_field",
]
