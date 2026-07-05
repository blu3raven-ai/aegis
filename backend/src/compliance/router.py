"""REST endpoints for compliance frameworks: catalog reads, framework/control CRUD, and PDF attestations."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.audit_log.recorder import ActorInfo, get_recorder
from src.compliance.models import (
    ComplianceFindingBriefResponse,
    ComplianceFrameworkBrief,
    ControlAssessmentResponse,
    ControlAssessmentUpsert,
    ControlCreate,
    MappingSuppressRequest,
    ControlFindingsResponse,
    ControlMappingResponse,
    ControlReadItem,
    ControlResponse,
    ControlUpdate,
    FindingControlsResponse,
    FrameworkControlsList,
    FrameworkCreate,
    FrameworkResponse,
    FrameworkWithControlsCreate,
    FrameworkSummaryResponse,
    FrameworksList,
    FrameworkUpdate,
    MappableFindingsResponse,
    MappingCreateRequest,
    MappingCreatedResponse,
)
from src.compliance.service import (
    ControlAlreadyExists,
    ControlNotFound,
    FrameworkAlreadyExists,
    FrameworkNotCustom,
    FrameworkNotFound,
    add_control,
    build_attestation_payload,
    create_framework,
    create_framework_with_controls,
    create_manual_mapping,
    delete_control,
    delete_framework,
    get_controls_for_finding,
    get_findings_for_control,
    get_framework,
    get_framework_summary,
    list_controls_for_framework,
    list_frameworks,
    search_mappable_findings,
    set_mapping_suppressed,
    update_control,
    update_framework,
    upsert_control_assessment,
)
from src.db.helpers import run_db
from src.exports.pdf import TEMPLATE_DIR, render_pdf
from src.authz.enforcement.dependencies import Permission
from src.authz.enforcement.scope import resolve_asset_ids_from_request
from src.authz.permissions.catalog import MANAGE_SETTINGS, VIEW_FINDINGS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])

# autoescape ON: payload mixes user/customer-supplied finding titles and source
# labels into the rendered HTML before WeasyPrint reads it.
_jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml", "j2"]),
)


@router.get(
    "/frameworks",
    response_model=FrameworksList,
    summary="List all registered compliance frameworks",
)
async def list_frameworks_handler(
    request: Request,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> FrameworksList:
    async def _query(session):
        return await list_frameworks(session)

    rows = run_db(_query)
    return FrameworksList(
        frameworks=[ComplianceFrameworkBrief(**row) for row in rows],
    )


@router.get(
    "/findings/{finding_id}/controls",
    response_model=FindingControlsResponse,
    summary="List control mappings for a finding",
)
async def get_finding_controls_handler(
    finding_id: int,
    request: Request,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> FindingControlsResponse:
    asset_ids = await resolve_asset_ids_from_request(request)

    async def _query(session):
        return await get_controls_for_finding(
            session, finding_id, asset_ids=asset_ids,
        )

    mappings = run_db(_query)
    return FindingControlsResponse(
        finding_id=finding_id,
        mappings=[
            ControlMappingResponse(
                framework=m["framework"],
                control_id=m["control_id"],
                title=m["title"],
                confidence=m["confidence"],
                rationale=m["rationale"],
            )
            for m in mappings
        ],
    )


@router.get(
    "/frameworks/{framework}/controls",
    response_model=FrameworkControlsList,
    summary="List reference controls for a framework",
)
async def list_framework_controls_handler(
    framework: str,
    request: Request,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> FrameworkControlsList:
    async def _query(session):
        if await get_framework(session, framework) is None:
            return None
        rows = await list_controls_for_framework(session, framework)
        return [
            ControlReadItem(
                id=r.id,
                framework=r.framework,
                control_id=r.control_id,
                title=r.title,
                description=r.description,
                category=r.category,
            )
            for r in rows
        ]

    rows = run_db(_query)
    if rows is None:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework}")
    return FrameworkControlsList(controls=rows)


@router.get(
    "/frameworks/{framework}/summary",
    response_model=FrameworkSummaryResponse,
    summary="Summarise a framework's controls with finding counts",
)
async def get_framework_summary_handler(
    framework: str,
    request: Request,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> FrameworkSummaryResponse:
    asset_ids = await resolve_asset_ids_from_request(request)

    async def _query(session):
        fw = await get_framework(session, framework)
        if fw is None:
            return None
        items = await get_framework_summary(session, framework, asset_ids=asset_ids)
        return fw, items

    result = run_db(_query)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework}")
    fw, items = result
    return FrameworkSummaryResponse(
        framework=framework,
        label=fw.label,
        controls=items,
    )


@router.get(
    "/frameworks/{framework}/controls/{control_id}/findings",
    response_model=ControlFindingsResponse,
    summary="List open findings mapped to a control",
)
async def get_control_findings_handler(
    framework: str,
    control_id: str,
    request: Request,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> ControlFindingsResponse:
    asset_ids = await resolve_asset_ids_from_request(request)

    async def _query(session):
        if await get_framework(session, framework) is None:
            return None
        # Include suppressed so the UI can render them greyed with a restore
        # action; they're already excluded from the control's counts/status.
        return await get_findings_for_control(
            session, framework, control_id, asset_ids=asset_ids, include_suppressed=True,
        )

    briefs = run_db(_query)
    if briefs is None:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework}")
    return ControlFindingsResponse(
        framework=framework,
        control_id=control_id,
        findings=[
            ComplianceFindingBriefResponse(
                id=b.id,
                tool=b.tool,
                org=b.org,
                repo=b.repo,
                severity=b.severity,
                state=b.state,
                identity_key=b.identity_key,
                confidence=b.confidence,
                rationale=b.rationale,
                mapping_id=b.mapping_id,
                suppressed=b.suppressed,
                manual=b.manual,
            )
            for b in briefs
        ],
    )


@router.get(
    "/frameworks/{framework}/controls/{control_id}/mappable-findings",
    response_model=MappableFindingsResponse,
    summary="Search findings that can be manually mapped to a control",
)
async def get_mappable_findings_handler(
    framework: str,
    control_id: str,
    request: Request,
    q: str | None = None,
    limit: int = 20,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> MappableFindingsResponse:
    """Open, in-scope findings not already mapped to this control — the
    candidates the analyst can add."""
    asset_ids = await resolve_asset_ids_from_request(request)
    limit = max(1, min(limit, 50))

    async def _query(session):
        if await get_framework(session, framework) is None:
            return None
        return await search_mappable_findings(
            session, framework, control_id, q=q, asset_ids=asset_ids, limit=limit,
        )

    items = run_db(_query)
    if items is None:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework}")
    # The service already returns validated MappableFindingItem rows.
    return MappableFindingsResponse(
        findings=items,
    )


@router.get("/frameworks/{framework}/attestation.pdf")
async def get_attestation_pdf(
    framework: str,
    request: Request,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> Response:
    """Stream the framework's attestation as a PDF."""
    asset_ids = await resolve_asset_ids_from_request(request)

    async def _query(session):
        if await get_framework(session, framework) is None:
            raise HTTPException(status_code=404, detail=f"Unknown framework: {framework}")
        return await build_attestation_payload(session, framework, asset_ids=asset_ids)

    payload = run_db(_query)
    template = _jinja_env.get_template("attestation.html.j2")
    html = template.render(**payload)
    pdf_bytes = render_pdf(html)

    user_sub = getattr(request.state, "user_sub", "system")
    get_recorder().record(
        action="compliance.attestation_exported",
        resource_type="framework",
        resource_id=framework,
        actor=ActorInfo(user_id=user_sub),
        metadata={"format": "pdf"},
    )

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = f"{framework}-attestation-{stamp}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# Write endpoints: custom frameworks and controls


def _identify_caller(request: Request) -> str:
    user_sub = getattr(request.state, "user_sub", None)
    if not user_sub:
        raise HTTPException(status_code=401, detail="missing caller identity")
    return user_sub


def _record_audit(
    *,
    request: Request,
    action: str,
    resource_type: str,
    resource_id: str,
    metadata: dict | None = None,
) -> None:
    get_recorder().record(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor=ActorInfo(user_id=_identify_caller(request)),
        metadata=metadata or {},
    )


@router.post(
    "/frameworks",
    status_code=201,
    response_model=FrameworkResponse,
    summary="Create a custom framework",
)
async def post_framework(
    body: FrameworkCreate,
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> FrameworkResponse:
    created_by = _identify_caller(request)

    async def _query(session):
        try:
            return await create_framework(
                session,
                framework_id=body.id,
                label=body.label,
                description=body.description,
                created_by_user_id=created_by,
            )
        except FrameworkAlreadyExists as exc:
            raise HTTPException(status_code=409, detail=f"framework {exc} already exists") from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    fw = run_db(_query)
    _record_audit(
        request=request,
        action="framework.created",
        resource_type="framework",
        resource_id=fw.id,
        metadata={"label": fw.label},
    )
    return FrameworkResponse.model_validate(fw)


@router.post(
    "/frameworks/with-controls",
    status_code=201,
    response_model=FrameworkResponse,
    summary="Create a custom framework and its controls atomically",
)
async def post_framework_with_controls(
    body: FrameworkWithControlsCreate,
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> FrameworkResponse:
    """Single-transaction create so a control failure can't orphan a
    half-created framework — nothing persists unless everything validates."""
    created_by = _identify_caller(request)

    async def _query(session):
        try:
            return await create_framework_with_controls(
                session,
                framework_id=body.id,
                label=body.label,
                description=body.description,
                controls=[c.model_dump() for c in body.controls],
                created_by_user_id=created_by,
            )
        except FrameworkAlreadyExists as exc:
            raise HTTPException(status_code=409, detail=f"framework {exc} already exists") from exc
        except ControlAlreadyExists as exc:
            raise HTTPException(status_code=422, detail=f"duplicate control id: {exc}") from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    fw = run_db(_query)
    _record_audit(
        request=request,
        action="framework.created",
        resource_type="framework",
        resource_id=fw.id,
        metadata={"label": fw.label, "control_count": len(body.controls)},
    )
    return FrameworkResponse.model_validate(fw)


@router.patch(
    "/frameworks/{framework_id}",
    response_model=FrameworkResponse,
    summary="Update a custom framework",
)
async def patch_framework(
    framework_id: str,
    body: FrameworkUpdate,
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> FrameworkResponse:
    patch_fields = body.model_dump(exclude_unset=True)
    if not patch_fields:
        raise HTTPException(status_code=422, detail="empty patch body")

    async def _query(session):
        try:
            return await update_framework(
                session,
                framework_id,
                label=body.label,
                description=body.description,
            )
        except FrameworkNotFound:
            raise HTTPException(status_code=404, detail="framework not found")
        except FrameworkNotCustom:
            raise HTTPException(status_code=403, detail="bundled frameworks cannot be modified")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    fw = run_db(_query)
    _record_audit(
        request=request,
        action="framework.updated",
        resource_type="framework",
        resource_id=fw.id,
        metadata={"fields": sorted(patch_fields.keys())},
    )
    return FrameworkResponse.model_validate(fw)


@router.delete(
    "/frameworks/{framework_id}",
    status_code=204,
    summary="Delete a custom framework",
)
async def del_framework(
    framework_id: str,
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> None:
    async def _query(session):
        try:
            await delete_framework(session, framework_id)
        except FrameworkNotFound:
            raise HTTPException(status_code=404, detail="framework not found")
        except FrameworkNotCustom:
            raise HTTPException(status_code=403, detail="bundled frameworks cannot be deleted")

    run_db(_query)
    _record_audit(
        request=request,
        action="framework.deleted",
        resource_type="framework",
        resource_id=framework_id,
    )


@router.post(
    "/frameworks/{framework_id}/controls",
    status_code=201,
    response_model=ControlResponse,
    summary="Add a control to a custom framework",
)
async def post_control(
    framework_id: str,
    body: ControlCreate,
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> ControlResponse:
    created_by = _identify_caller(request)

    async def _query(session):
        try:
            return await add_control(
                session,
                framework_id,
                control_id=body.control_id,
                title=body.title,
                description=body.description,
                category=body.category,
                created_by_user_id=created_by,
            )
        except FrameworkNotFound:
            raise HTTPException(status_code=404, detail="framework not found")
        except FrameworkNotCustom:
            raise HTTPException(status_code=403, detail="bundled frameworks are immutable")
        except ControlAlreadyExists:
            raise HTTPException(status_code=409, detail="control already exists in this framework")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    ctrl = run_db(_query)
    _record_audit(
        request=request,
        action="framework_control.created",
        resource_type="framework_control",
        resource_id=f"{framework_id}:{ctrl.control_id}",
        metadata={"title": ctrl.title},
    )
    return ControlResponse.model_validate(ctrl)


@router.patch(
    "/frameworks/{framework_id}/controls/{control_id}",
    response_model=ControlResponse,
    summary="Update a custom-framework control",
)
async def patch_control(
    framework_id: str,
    control_id: str,
    body: ControlUpdate,
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> ControlResponse:
    patch_fields = body.model_dump(exclude_unset=True)
    if not patch_fields:
        raise HTTPException(status_code=422, detail="empty patch body")

    async def _query(session):
        try:
            return await update_control(
                session,
                framework_id,
                control_id,
                title=body.title,
                description=body.description,
                category=body.category,
            )
        except FrameworkNotFound:
            raise HTTPException(status_code=404, detail="framework not found")
        except FrameworkNotCustom:
            raise HTTPException(status_code=403, detail="bundled frameworks are immutable")
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="control not found")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    ctrl = run_db(_query)
    _record_audit(
        request=request,
        action="framework_control.updated",
        resource_type="framework_control",
        resource_id=f"{framework_id}:{ctrl.control_id}",
        metadata={"fields": sorted(patch_fields.keys())},
    )
    return ControlResponse.model_validate(ctrl)


@router.delete(
    "/frameworks/{framework_id}/controls/{control_id}",
    status_code=204,
    summary="Delete a custom-framework control",
)
async def del_control(
    framework_id: str,
    control_id: str,
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> None:
    async def _query(session):
        try:
            await delete_control(session, framework_id, control_id)
        except FrameworkNotFound:
            raise HTTPException(status_code=404, detail="framework not found")
        except FrameworkNotCustom:
            raise HTTPException(status_code=403, detail="bundled frameworks are immutable")
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="control not found")

    run_db(_query)
    _record_audit(
        request=request,
        action="framework_control.deleted",
        resource_type="framework_control",
        resource_id=f"{framework_id}:{control_id}",
    )


@router.put(
    "/frameworks/{framework}/controls/{control_id}/assessment",
    response_model=ControlAssessmentResponse,
    summary="Set or clear a control's manual attestation and evidence",
)
async def put_control_assessment(
    framework: str,
    control_id: str,
    body: ControlAssessmentUpsert,
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> ControlAssessmentResponse:
    """Attest a control — bundled or custom. Unlike control CRUD, this is allowed
    on bundled frameworks: you sign off on SOC 2 / ISO / PCI controls, you don't
    edit them."""
    async def _query(session):
        try:
            return await upsert_control_assessment(
                session,
                framework,
                control_id,
                status=body.status,
                evidence_note=body.evidence_note,
                evidence_url=body.evidence_url,
                owner_user_id=body.owner_user_id,
                due_date=body.due_date,
                user_id=_identify_caller(request),
            )
        except FrameworkNotFound:
            raise HTTPException(status_code=404, detail="framework not found")
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="control not found")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    row = run_db(_query)
    _record_audit(
        request=request,
        action="compliance.control_assessed",
        resource_type="compliance_control",
        resource_id=f"{framework}:{control_id}",
        metadata={"status": row.status or "auto"},
    )
    return ControlAssessmentResponse(
        framework=row.framework,
        control_id=row.control_id,
        status=row.status,
        evidence_note=row.evidence_note,
        evidence_url=row.evidence_url,
        owner_user_id=row.owner_user_id,
        due_date=row.due_date.isoformat() if row.due_date else None,
        assessed_by=row.assessed_by_user_id,
        assessed_at=row.assessed_at.isoformat() if row.assessed_at else None,
    )


@router.post(
    "/frameworks/{framework}/controls/{control_id}/mappings",
    status_code=201,
    response_model=MappingCreatedResponse,
    summary="Manually map a finding to a control",
)
async def post_control_mapping(
    framework: str,
    control_id: str,
    body: MappingCreateRequest,
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> MappingCreatedResponse:
    """Add a finding→control mapping the auto-mapper missed. Scoped to the
    caller's assets — mapping an out-of-scope finding 404s rather than letting
    the caller probe finding ids."""
    asset_ids = await resolve_asset_ids_from_request(request)

    async def _query(session):
        try:
            return await create_manual_mapping(
                session, framework, control_id, body.finding_id, asset_ids=asset_ids,
            )
        except FrameworkNotFound:
            raise HTTPException(status_code=404, detail="framework not found")
        except ControlNotFound:
            raise HTTPException(status_code=404, detail="control not found")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    result = run_db(_query)
    if result is None:
        raise HTTPException(status_code=404, detail="finding not found")
    row, created = result
    if created:
        _record_audit(
            request=request,
            action="compliance.mapping_added",
            resource_type="compliance_mapping",
            resource_id=str(row.id),
            metadata={
                "framework": framework,
                "control_id": control_id,
                "finding_id": body.finding_id,
            },
        )
    return MappingCreatedResponse(
        mapping_id=row.id, finding_id=body.finding_id, created=created,
    )


@router.patch(
    "/mappings/{mapping_id}",
    status_code=204,
    summary="Suppress or restore an auto-generated finding→control mapping",
)
async def patch_mapping_suppression(
    mapping_id: int,
    body: MappingSuppressRequest,
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> Response:
    """Mark an auto-mapping as a false positive (or restore it). Scoped to the
    caller's assets — a mapping on an out-of-scope finding 404s rather than
    letting the caller probe mapping ids."""
    asset_ids = await resolve_asset_ids_from_request(request)

    async def _query(session):
        return await set_mapping_suppressed(
            session,
            mapping_id,
            suppressed=body.suppressed,
            reason=body.reason,
            user_id=_identify_caller(request),
            asset_ids=asset_ids,
        )

    row = run_db(_query)
    if row is None:
        raise HTTPException(status_code=404, detail="mapping not found")
    _record_audit(
        request=request,
        action="compliance.mapping_suppressed" if body.suppressed else "compliance.mapping_restored",
        resource_type="compliance_mapping",
        resource_id=str(mapping_id),
        metadata={"framework": row.framework, "control_id": row.control_id},
    )
    return Response(status_code=204)
