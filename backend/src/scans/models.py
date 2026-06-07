"""Pydantic I/O models for /api/v1/repos/{repo_id}/scan and /api/v1/scans/{scan_id}."""
from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator


_VALID_SCANNERS = {"dependencies", "code_scanning", "container_scanning", "secrets", "iac"}
_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")


class ScanRequest(BaseModel):
    commit_sha: str = Field(..., description="Git commit SHA to scan (7-64 hex chars)")
    scanner_types: list[str] | None = Field(
        None,
        description="Optional list of scanner types to run. Defaults to a standard set.",
    )

    @field_validator("commit_sha")
    @classmethod
    def _validate_sha(cls, v: str) -> str:
        if not _SHA_RE.match(v):
            raise ValueError("commit_sha must be 7-64 lowercase hex characters")
        return v

    @field_validator("scanner_types")
    @classmethod
    def _validate_scanners(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        unknown = [s for s in v if s not in _VALID_SCANNERS]
        if unknown:
            raise ValueError(f"Unknown scanner_types: {unknown}")
        return v


class FindingCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanSubmissionResponse(BaseModel):
    scan_id: str
    repo_id: str
    commit_sha: str
    scanner_types: list[str]
    status: str = Field(..., description="queued | running | completed | failed")
    submitted_at: str
    submitted_by: str


class ScanDetailResponse(BaseModel):
    scan_id: str
    repo_id: str
    commit_sha: str
    scanner_types: list[str]
    status: str
    submitted_at: str
    submitted_by: str
    started_at: str | None = None
    finished_at: str | None = None
    finding_counts: FindingCounts | None = None
    error: str | None = None
    archived: bool = False
