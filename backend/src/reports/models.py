"""Pydantic I/O models for /api/v1/reports."""
from __future__ import annotations
from typing import Literal
from pydantic import BaseModel


class FindingsReportFilters(BaseModel):
    severity: list[str] | None = None
    scanner: list[str] | None = None
    state: list[str] | None = None
    repo: str | None = None


class GenerateReportRequest(BaseModel):
    report_type: Literal["findings", "posture"]
    format: Literal["json", "csv"] = "json"
    title: str | None = None
    filters: FindingsReportFilters | None = None
    # Compliance opt-in — when true, the report includes archived findings
    # alongside the live set. Default is false so reports match the standard
    # operational view shown elsewhere in the product.
    include_archived: bool = False


class ReportSummary(BaseModel):
    id: int
    org: str
    title: str
    report_type: str
    format: str
    status: str
    row_count: int | None
    file_size_bytes: int | None
    created_by: str
    created_at: str
    expires_at: str


class ReportDetail(ReportSummary):
    filters: dict | None
    error: str | None
    download_url: str | None


class ReportsListResponse(BaseModel):
    reports: list[ReportSummary]
    total: int
