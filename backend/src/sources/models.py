"""Pydantic schemas for /api/v1/sources.

Sources are a polymorphic surface over the Asset table: each entry carries a
`type` discriminator (`repo` | `image` | `cloud`) plus a shared set of common
fields, with a nested type-specific block for fields that only make sense for
one asset type. Adding a new asset type means adding a Pydantic model +
discriminator branch and a per-type list subroute — no schema rewrites of the
existing branches.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


SourceType = Literal["repo", "image", "cloud"]


class FindingCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class _CommonSourceFields(BaseModel):
    """Fields every source carries regardless of type."""
    asset_id: str
    display_name: str | None
    last_scanned_at: str | None = None
    finding_counts: FindingCounts


# ── Repo-specific blocks ─────────────────────────────────────────────────────


class RepoExtras(BaseModel):
    last_scanned_sha: str | None = None
    manifest_set_hash: str | None = None
    scanners_with_coverage: list[str] = []
    coverage_status: str = "never"  # 'fresh' | 'stale' | 'never'
    source_url: str | None = None


class RepoSourceSummary(_CommonSourceFields):
    type: Literal["repo"] = "repo"
    repo: RepoExtras


# ── Image-specific blocks ────────────────────────────────────────────────────


class ImageExtras(BaseModel):
    image_digest: str | None = None
    image_name: str | None = None
    image_tag: str | None = None
    layer_count: int | None = None
    size_bytes: int | None = None
    base_os: str | None = None
    repos: list[str] = []


class ImageSourceSummary(_CommonSourceFields):
    type: Literal["image"] = "image"
    image: ImageExtras


# ── Cloud-specific blocks (placeholder — no dispatch wired) ─────────────────


class CloudExtras(BaseModel):
    provider: str | None = None
    account_id: str | None = None
    regions: list[str] = []


class CloudSourceSummary(_CommonSourceFields):
    type: Literal["cloud"] = "cloud"
    cloud: CloudExtras


# ── Discriminated unions ─────────────────────────────────────────────────────


SourceSummary = RepoSourceSummary | ImageSourceSummary | CloudSourceSummary


class ScanRunRow(BaseModel):
    scan_id: str
    scanner_type: str
    status: str
    started_at: str
    duration_ms: int | None = None
    findings_count: int = 0


class FindingRow(BaseModel):
    id: int
    tool: str
    severity: str | None
    state: str
    identity_key: str
    asset_id: str | None
    first_seen_at: str
    last_seen_at: str


class _DetailMixin(BaseModel):
    scan_history: list[ScanRunRow] = []
    active_findings: list[FindingRow] = []


class RepoSourceDetail(RepoSourceSummary, _DetailMixin):
    default_branch: str | None = None


class ImageSourceDetail(ImageSourceSummary, _DetailMixin):
    pass


class CloudSourceDetail(CloudSourceSummary, _DetailMixin):
    pass


SourceDetail = RepoSourceDetail | ImageSourceDetail | CloudSourceDetail


# ── List responses ───────────────────────────────────────────────────────────


class SourceListResponse(BaseModel):
    """Polymorphic combined list — items of any type, with `type` discriminator."""
    sources: list[SourceSummary] = Field(default_factory=list)
    next_cursor: str | None = None
    total_count: int | None = None


class RepoListResponse(BaseModel):
    sources: list[RepoSourceSummary] = Field(default_factory=list)
    next_cursor: str | None = None
    total_count: int | None = None


class ImageListResponse(BaseModel):
    sources: list[ImageSourceSummary] = Field(default_factory=list)
    next_cursor: str | None = None
    total_count: int | None = None
