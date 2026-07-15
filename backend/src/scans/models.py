"""Pydantic I/O models for the /api/v1/scans router family."""
from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator, model_validator


_VALID_SCANNERS = {"dependencies_scanning", "code_scanning", "container_scanning", "secret_scanning", "iac_scanning", "agent_scanning", "deep_audit"}
_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")


class ManualScanRequest(BaseModel):
    """Polymorphic manual scan trigger.

    asset_id is the only universally required field. Asset.type determines which
    extra fields apply: commit_sha for repos, image_digest for images, neither
    for cloud. Per-type required-field validation happens server-side inside
    submit_scan() after the Asset is loaded.
    """
    asset_id: str = Field(..., description="Asset UUID to scan (any type)")
    commit_sha: str | None = Field(
        None,
        description="Git commit SHA (7-64 hex chars). Required when asset_id resolves to a repo.",
    )
    image_digest: str | None = Field(
        None,
        description="Container image digest (e.g. sha256:...). Optional override when asset_id resolves to an image.",
    )
    scanner_types: list[str] | None = Field(
        None,
        description="Optional list of scanner types. Defaults to the standard set for the asset's type.",
    )

    @field_validator("commit_sha")
    @classmethod
    def _validate_sha(cls, v: str | None) -> str | None:
        if v is None:
            return None
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


class CIScanRequest(BaseModel):
    # Either source_id (explicit) or repo + source_type (auto-resolved on
    # ingestion) must be provided. Resolving by repo lets CI omit the source id.
    source_id: str | None = Field(None, description="Source UUID the CI key is authorised to scan")
    repo: str | None = Field(None, max_length=512, description="owner/name — resolved to a source on ingestion")
    source_type: str | None = Field(None, max_length=32, description="github | gitlab | bitbucket | azure_devops")
    commit_sha: str = Field(..., min_length=4, max_length=64, pattern=r"^[0-9a-fA-F]{4,64}$")
    branch: str | None = Field(None, max_length=255)
    pr_number: int | None = Field(None, ge=1)
    trigger_metadata: dict | None = None

    @model_validator(mode="after")
    def _require_identity(self) -> "CIScanRequest":
        if not self.source_id and not (self.repo and self.source_type):
            raise ValueError("either source_id or (repo + source_type) is required")
        return self


class FindingCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class VerificationSummary(BaseModel):
    """Aggregate LLM verification telemetry for a scan."""
    confirmed: int = 0
    needs_runtime_verification: int = 0
    needs_verify: int = 0
    possible: int = 0
    ruled_out: int = 0
    legacy: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    model: str | None = None


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
    verification_summary: VerificationSummary | None = None
