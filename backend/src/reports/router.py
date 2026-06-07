"""REST endpoints for /api/v1/reports."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from src.reports.models import (
    GenerateReportRequest,
    ReportDetail,
    ReportSummary,
    ReportsListResponse,
)
from src.reports.service import (
    delete_report,
    generate_report,
    get_download_url,
    get_report,
    list_reports,
)
from src.settings.router import require_permission

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


def _to_summary(row) -> ReportSummary:
    return ReportSummary(
        id=row.id,
        org=row.org,
        title=row.title,
        report_type=row.report_type,
        format=row.format,
        status=row.status,
        row_count=row.row_count,
        file_size_bytes=row.file_size_bytes,
        created_by=row.created_by,
        created_at=row.created_at.isoformat(),
        expires_at=row.expires_at.isoformat(),
    )


def _to_detail(row) -> ReportDetail:
    return ReportDetail(
        **_to_summary(row).model_dump(),
        filters=row.filters,
        error=row.error,
        download_url=get_download_url(row),
    )


@router.post("", status_code=201, response_model=ReportDetail, summary="Generate a report")
def create_report(body: GenerateReportRequest, request: Request) -> ReportDetail:
    require_permission(request, "view_findings")
    if body.report_type == "posture" and body.format == "csv":
        raise HTTPException(
            status_code=422,
            detail="Posture reports only support JSON format",
        )
    org: str = getattr(request.state, "user_org", None) or "default"
    created_by: str = (
        getattr(request.state, "user_email", None)
        or getattr(request.state, "user_sub", None)
        or "unknown"
    )
    filters_dict = body.filters.model_dump(exclude_none=True) if body.filters else None
    try:
        row = generate_report(
            org=org,
            report_type=body.report_type,
            fmt=body.format,
            title=body.title,
            filters=filters_dict,
            created_by=created_by,
            include_archived=body.include_archived,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _to_detail(row)


@router.get("", response_model=ReportsListResponse, summary="List reports")
def list_reports_endpoint(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ReportsListResponse:
    require_permission(request, "view_findings")
    org: str = getattr(request.state, "user_org", None) or "default"
    rows, total = list_reports(org=org, limit=limit, offset=offset)
    return ReportsListResponse(reports=[_to_summary(r) for r in rows], total=total)


@router.get("/{report_id}", response_model=ReportDetail, summary="Get report detail + download URL")
def get_report_endpoint(report_id: int, request: Request) -> ReportDetail:
    require_permission(request, "view_findings")
    org: str = getattr(request.state, "user_org", None) or "default"
    row = get_report(report_id=report_id, org=org)
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    return _to_detail(row)


@router.delete("/{report_id}", status_code=204, summary="Delete a report")
def delete_report_endpoint(report_id: int, request: Request) -> None:
    require_permission(request, "view_findings")
    org: str = getattr(request.state, "user_org", None) or "default"
    if not delete_report(report_id=report_id, org=org):
        raise HTTPException(status_code=404, detail="Report not found")
