"""REST endpoints for compliance framework mapping."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.audit_log.recorder import ActorInfo, get_recorder
from src.compliance.models import (
    ControlCreate,
    ControlResponse,
    ControlUpdate,
    FrameworkControlSchema,
    FrameworkCreate,
    FrameworkResponse,
    FrameworkUpdate,
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
    delete_control,
    delete_framework,
    get_controls_for_finding,
    get_findings_for_control,
    get_framework,
    get_framework_summary,
    list_controls_for_framework,
    list_frameworks,
    update_control,
    update_framework,
)
from src.db.helpers import run_db
from src.exports.pdf import TEMPLATE_DIR, render_pdf
from src.settings.router import require_permission
from src.shared.scope import resolve_asset_ids_from_request

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])

# autoescape ON: payload mixes user/customer-supplied finding titles and source
# labels into the rendered HTML before WeasyPrint reads it.
_jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml", "j2"]),
)


@router.get("/frameworks")
async def get_frameworks() -> list[dict[str, str]]:
    """List supported compliance frameworks."""
    return run_db(list_frameworks)


@router.get("/frameworks/{framework}/controls")
def get_controls(framework: str) -> list[dict[str, Any]]:
    """List all controls in a given framework."""
    async def _query(session):
        if await get_framework(session, framework) is None:
            raise HTTPException(status_code=404, detail=f"Unknown framework: {framework}")
        rows = await list_controls_for_framework(session, framework)
        return [FrameworkControlSchema.model_validate(r).model_dump() for r in rows]

    return run_db(_query)


@router.get("/frameworks/{framework}/summary")
async def get_summary(framework: str, request: Request) -> dict[str, Any]:
    """Return per-control finding counts scoped to the caller's accessible assets."""
    require_permission(request, "view_findings")
    asset_ids = await resolve_asset_ids_from_request(request)

    async def _query(session):
        fw = await get_framework(session, framework)
        if fw is None:
            raise HTTPException(status_code=404, detail=f"Unknown framework: {framework}")
        items = await get_framework_summary(session, framework, asset_ids=asset_ids)
        return {
            "framework": framework,
            "label": fw.label,
            "controls": [item.model_dump() for item in items],
        }

    return run_db(_query)


@router.get("/frameworks/{framework}/attestation.pdf")
async def get_attestation_pdf(framework: str, request: Request) -> Response:
    """Stream the framework's attestation as a PDF."""
    require_permission(request, "view_findings")
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


@router.get("/controls/{framework}/{control_id}/findings")
async def get_findings_by_control(
    framework: str, control_id: str, request: Request
) -> dict[str, Any]:
    """Return open findings mapped to a specific control, scoped to the caller's accessible assets."""
    require_permission(request, "view_findings")
    asset_ids = await resolve_asset_ids_from_request(request)

    async def _query(session):
        if await get_framework(session, framework) is None:
            raise HTTPException(status_code=404, detail=f"Unknown framework: {framework}")
        briefs = await get_findings_for_control(
            session, framework, control_id, asset_ids=asset_ids
        )
        return {
            "framework": framework,
            "control_id": control_id,
            "findings": [b.model_dump() for b in briefs],
        }

    return run_db(_query)


@router.get("/findings/{finding_id}/controls")
def get_controls_for_finding_endpoint(finding_id: int) -> dict[str, Any]:
    """Return all compliance controls a finding violates."""
    async def _query(session):
        return await get_controls_for_finding(session, finding_id)

    mappings = run_db(_query)
    return {"finding_id": finding_id, "controls": mappings}


# ---------------------------------------------------------------------------
# Write endpoints: custom frameworks and controls
# ---------------------------------------------------------------------------


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
async def post_framework(body: FrameworkCreate, request: Request) -> FrameworkResponse:
    require_permission(request, "manage_settings")
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


@router.patch(
    "/frameworks/{framework_id}",
    response_model=FrameworkResponse,
    summary="Update a custom framework",
)
async def patch_framework(
    framework_id: str, body: FrameworkUpdate, request: Request,
) -> FrameworkResponse:
    require_permission(request, "manage_settings")
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
async def del_framework(framework_id: str, request: Request) -> None:
    require_permission(request, "manage_settings")

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
    framework_id: str, body: ControlCreate, request: Request,
) -> ControlResponse:
    require_permission(request, "manage_settings")
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
    framework_id: str, control_id: str, body: ControlUpdate, request: Request,
) -> ControlResponse:
    require_permission(request, "manage_settings")
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
async def del_control(framework_id: str, control_id: str, request: Request) -> None:
    require_permission(request, "manage_settings")

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
