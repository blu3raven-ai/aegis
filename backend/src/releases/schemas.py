"""Pydantic I/O models for /api/v1/releases."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class ReleaseTriggeredBy(BaseModel):
    actor_type: Literal["user", "ci"]
    actor_id: str
    display_name: str


class ReleaseSummary(BaseModel):
    scan_id: str
    repo_id: str
    repo: str
    ref: str | None = None
    commit_sha: str
    short_sha: str
    verdict: Literal["go", "warn", "no_go", "pending", "unknown"]
    blocker_count: int
    warn_count: int
    scanner_count: int
    status: Literal["queued", "running", "completed", "failed"]
    started_at: str | None = None
    finished_at: str | None = None
    triggered_by: ReleaseTriggeredBy


class ReleaseListResponse(BaseModel):
    releases: list[ReleaseSummary]
    next_cursor: str | None = None


class BlockerDiffRow(BaseModel):
    finding_id: int
    diff_status: Literal["new", "persisted", "gone", "fixed"]
    severity: str
    title: str
    file_path: str | None = None
    cve_id: str | None = None
    cwe_id: str | None = None
    scanner: str
    first_seen_at: str
    introduced_by_commit_sha: str | None = None
    is_kev: bool
    epss_score: float | None = None


class ReleaseDetail(ReleaseSummary):
    baseline_scan_id: str | None = None
    baseline_ref: str | None = None
    baseline_taken_at: str | None = None
    scanners_run: list[str]
    blockers_diff: list[BlockerDiffRow]
    improvements: list[BlockerDiffRow]
