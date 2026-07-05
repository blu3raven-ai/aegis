"""Pydantic I/O models for the /api/v1/images endpoint."""
from __future__ import annotations

from pydantic import BaseModel, Field


class FindingCounts(BaseModel):
    critical: int = Field(0, description="Open critical findings on this image")
    high: int = Field(0, description="Open high findings on this image")
    medium: int = Field(0, description="Open medium findings on this image")
    low: int = Field(0, description="Open low findings on this image")


class ImageRow(BaseModel):
    image_digest: str = Field(..., description="sha256 digest of the image")
    image_name: str | None = Field(None, description="Registry path, e.g. registry/owner/repo")
    image_tag: str | None = Field(None, description="Tag, e.g. v1.2.3 or latest")
    first_seen_at: str = Field(..., description="ISO 8601 of the earliest finding on this image")
    last_scanned_at: str | None = Field(None, description="ISO 8601 of the most recent scan touching this image, or null if unknown")
    finding_counts: FindingCounts
    repos: list[str] = Field(default_factory=list, description="repo strings (org/repo) that contain this image")
    layer_count: int | None = Field(None, description="Number of layers in the image, or null if not derivable from ingested data")
    size_bytes: int | None = Field(None, description="Total image size in bytes, or null if unavailable")
    base_os: str | None = Field(None, description="Base OS string (e.g. 'alpine:3.18'), or null if not extractable")


class ImageListResponse(BaseModel):
    images: list[ImageRow]
    next_cursor: str | None = Field(None, description="Opaque cursor for the next page, or null at end")
    total_count: int = Field(..., description="Total distinct images for the org")
