"""Pydantic I/O models for /api/v1/findings/reports."""
from __future__ import annotations
from typing import Literal
from pydantic import BaseModel


class FindingsReportFilters(BaseModel):
    severity: list[str] | None = None
    scanner: list[str] | None = None
    state: list[str] | None = None
    repo: str | None = None


class GenerateReportRequest(BaseModel):
    report_type: Literal["findings", "posture", "executive", "risk_register", "soc2_evidence"]
    format: Literal["json", "csv", "pdf", "zip"] = "json"
    title: str | None = None
    filters: FindingsReportFilters | None = None
    # Compliance opt-in — when true, the report includes archived findings
    # alongside the live set. Default is false so reports match the standard
    # operational view shown elsewhere in the product.
    include_archived: bool = False


class ReportSummary(BaseModel):
    id: int
    title: str
    report_type: str
    format: str
    status: str
    row_count: int | None
    file_size_bytes: int | None
    created_by: str
    created_at: str
    expires_at: str
    # Surfaced on the list too (not just detail) so the history table can offer a
    # working Download for completed reports and a reason for failed ones.
    error: str | None = None
    download_url: str | None = None


class ReportDetail(ReportSummary):
    filters: dict | None


class ReportsListResponse(BaseModel):
    reports: list[ReportSummary]
    total: int


class ScheduledReportCreate(BaseModel):
    name: str
    report_type: Literal["findings", "posture", "executive", "risk_register", "soc2_evidence"]
    format: Literal["json", "csv", "pdf", "zip"]
    schedule_type: Literal["simple", "cron"]
    schedule_value: str
    filters: dict | None = None
    destination_ids: list[int] = []
    enabled: bool = True


class ScheduledReportUpdate(BaseModel):
    name: str | None = None
    report_type: Literal["findings", "posture", "executive", "risk_register", "soc2_evidence"] | None = None
    format: Literal["json", "csv", "pdf", "zip"] | None = None
    schedule_type: Literal["simple", "cron"] | None = None
    schedule_value: str | None = None
    filters: dict | None = None
    destination_ids: list[int] | None = None
    enabled: bool | None = None


class ScheduledReportResponse(BaseModel):
    id: int
    name: str
    report_type: str
    format: str
    schedule_type: str
    schedule_value: str
    filters: dict
    destination_ids: list[int]
    created_by: str
    enabled: bool
    last_run_at: str | None
    last_run_status: str | None
    last_run_error: str | None
    created_at: str
    updated_at: str


class ScheduledReportsListResponse(BaseModel):
    items: list[ScheduledReportResponse]
