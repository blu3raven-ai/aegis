"""REST endpoints for /api/v1/reports."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from src.audit_log.recorder import ActorInfo, get_recorder
from src.reports.models import (
    GenerateReportRequest,
    ReportDetail,
    ReportSummary,
    ReportsListResponse,
    ScheduledReportCreate,
    ScheduledReportResponse,
    ScheduledReportUpdate,
    ScheduledReportsListResponse,
)
from src.reports.scheduled import (
    ScheduledReportNotFound,
    create_schedule,
    delete_schedule,
    get_schedule,
    list_schedules,
    update_schedule,
)
from src.reports.service import (
    delete_report,
    generate_report,
    get_download_url,
    get_report,
    list_reports,
)
from src.settings.router import require_permission
from src.shared.scope import resolve_asset_ids_from_request

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


def _to_summary(row) -> ReportSummary:
    return ReportSummary(
        id=row.id,
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


def _identify_caller(request: Request) -> str:
    caller = (
        getattr(request.state, "user_email", None)
        or getattr(request.state, "user_sub", None)
    )
    if not caller:
        raise HTTPException(status_code=401, detail="missing caller identity")
    return caller


@router.post("", status_code=201, response_model=ReportDetail, summary="Generate a report")
async def create_report(body: GenerateReportRequest, request: Request) -> ReportDetail:
    require_permission(request, "view_findings")
    if body.report_type == "posture" and body.format == "csv":
        raise HTTPException(
            status_code=422,
            detail="Posture reports do not support CSV format",
        )
    created_by = _identify_caller(request)
    asset_ids = await resolve_asset_ids_from_request(request)
    filters_dict = body.filters.model_dump(exclude_none=True) if body.filters else None
    try:
        row = generate_report(
            report_type=body.report_type,
            fmt=body.format,
            title=body.title,
            filters=filters_dict,
            created_by=created_by,
            include_archived=body.include_archived,
            asset_ids=asset_ids,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _to_detail(row)


@router.get("", response_model=ReportsListResponse, summary="List reports")
async def list_reports_endpoint(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ReportsListResponse:
    require_permission(request, "view_findings")
    viewer_id = _identify_caller(request)
    viewer_asset_ids = await resolve_asset_ids_from_request(request)
    rows, total = list_reports(
        viewer_id=viewer_id,
        viewer_asset_ids=viewer_asset_ids,
        limit=limit,
        offset=offset,
    )
    return ReportsListResponse(reports=[_to_summary(r) for r in rows], total=total)


def _record_audit(*, request: Request, action: str, schedule_id: int, metadata: dict | None = None) -> None:
    user_sub = getattr(request.state, "user_sub", "system")
    get_recorder().record(
        action=action,
        resource_type="scheduled_report",
        resource_id=str(schedule_id),
        actor=ActorInfo(user_id=user_sub),
        metadata=metadata or {},
    )


@router.post("/scheduled", status_code=201, response_model=ScheduledReportResponse,
             summary="Create a scheduled report")
async def create_scheduled_report(body: ScheduledReportCreate, request: Request) -> ScheduledReportResponse:
    require_permission(request, "view_findings")
    created_by = _identify_caller(request)
    asset_ids = await resolve_asset_ids_from_request(request)
    try:
        result = create_schedule(body.model_dump(), created_by=created_by, asset_ids=asset_ids)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    _record_audit(request=request, action="scheduled_report.created", schedule_id=result["id"],
                  metadata={"name": result["name"], "report_type": result["report_type"]})
    return ScheduledReportResponse(**result)


@router.get("/scheduled", response_model=ScheduledReportsListResponse,
            summary="List scheduled reports")
async def list_scheduled_reports(request: Request) -> ScheduledReportsListResponse:
    require_permission(request, "view_findings")
    items = list_schedules()
    return ScheduledReportsListResponse(items=[ScheduledReportResponse(**i) for i in items])


@router.get("/scheduled/{schedule_id}", response_model=ScheduledReportResponse,
            summary="Get a scheduled report by id")
async def get_scheduled_report(schedule_id: int, request: Request) -> ScheduledReportResponse:
    require_permission(request, "view_findings")
    result = get_schedule(schedule_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scheduled report not found")
    return ScheduledReportResponse(**result)


@router.patch("/scheduled/{schedule_id}", response_model=ScheduledReportResponse,
              summary="Update a scheduled report")
async def update_scheduled_report(schedule_id: int, body: ScheduledReportUpdate, request: Request) -> ScheduledReportResponse:
    require_permission(request, "view_findings")
    patch = body.model_dump(exclude_unset=True)
    if not patch:
        raise HTTPException(status_code=422, detail="empty patch body")
    try:
        result = update_schedule(schedule_id, patch)
    except ScheduledReportNotFound:
        raise HTTPException(status_code=404, detail="Scheduled report not found")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    _record_audit(request=request, action="scheduled_report.updated", schedule_id=schedule_id,
                  metadata={"fields": sorted(patch.keys())})
    return ScheduledReportResponse(**result)


@router.delete("/scheduled/{schedule_id}", status_code=204,
               summary="Delete a scheduled report")
async def delete_scheduled_report(schedule_id: int, request: Request) -> None:
    require_permission(request, "view_findings")
    if not delete_schedule(schedule_id):
        raise HTTPException(status_code=404, detail="Scheduled report not found")
    _record_audit(request=request, action="scheduled_report.deleted", schedule_id=schedule_id)


@router.get("/{report_id}", response_model=ReportDetail, summary="Get report detail + download URL")
async def get_report_endpoint(report_id: int, request: Request) -> ReportDetail:
    require_permission(request, "view_findings")
    viewer_id = _identify_caller(request)
    viewer_asset_ids = await resolve_asset_ids_from_request(request)
    row = get_report(report_id=report_id, viewer_id=viewer_id, viewer_asset_ids=viewer_asset_ids)
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    return _to_detail(row)


@router.delete("/{report_id}", status_code=204, summary="Delete a report")
async def delete_report_endpoint(report_id: int, request: Request) -> None:
    require_permission(request, "view_findings")
    viewer_id = _identify_caller(request)
    viewer_asset_ids = await resolve_asset_ids_from_request(request)
    if not delete_report(
        report_id=report_id,
        viewer_id=viewer_id,
        viewer_asset_ids=viewer_asset_ids,
    ):
        raise HTTPException(status_code=404, detail="Report not found")
