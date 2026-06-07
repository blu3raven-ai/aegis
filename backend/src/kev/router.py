"""KEV catalog API router.

Endpoints:
  GET /api/v1/kev/recent              — recent catalog additions
  GET /api/v1/kev/exposure-summary    — scope-aware KEV overlap with open findings
  GET /api/v1/kev/{cve_id}            — single entry lookup

The order of route definitions matters: literal paths (recent, exposure-summary)
must be registered before the path-param route {cve_id} to avoid the parameter
capturing them as CVE IDs.

Route handlers are synchronous (FastAPI runs them in a thread pool) because
KevService uses run_db() internally — consistent with api_keys and fleet routers.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from src.kev.service import KevService
from src.settings.router import require_permission
from src.shared.scope import resolve_asset_ids_from_request

router = APIRouter(prefix="/api/v1/kev", tags=["kev"])

_service = KevService()


def _entry_dict(entry) -> dict:
    return {
        "cve_id": entry.cve_id,
        "vendor_project": entry.vendor_project,
        "product": entry.product,
        "vulnerability_name": entry.vulnerability_name,
        "date_added": entry.date_added.isoformat() if entry.date_added else None,
        "short_description": entry.short_description,
        "required_action": entry.required_action,
        "due_date": entry.due_date.isoformat() if entry.due_date else None,
        "known_ransomware_use": entry.known_ransomware_use,
        "notes": entry.notes,
        "cwes": entry.cwes or [],
        "ingested_at": entry.ingested_at.isoformat() if entry.ingested_at else None,
    }


@router.get("/recent")
def list_recent(days: int = Query(default=30, ge=1, le=365)) -> JSONResponse:
    """Return KEV entries added to the catalog within the last N days."""
    entries = _service.list_recent(days=days)
    return JSONResponse({"entries": [_entry_dict(e) for e in entries], "count": len(entries)})


@router.get("/exposure-summary")
async def exposure_summary(request: Request) -> JSONResponse:
    """Compute CISA KEV overlap for the caller's accessible findings."""
    require_permission(request, "view_findings")
    asset_ids = await resolve_asset_ids_from_request(request)
    return JSONResponse(_service.get_exposure_summary(asset_ids=asset_ids))


@router.get("/{cve_id}")
def get_entry(cve_id: str) -> JSONResponse:
    """Fetch a single KEV entry by CVE ID (e.g. CVE-2024-12345)."""
    entry = _service.get_entry(cve_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} is not in the CISA KEV catalog")
    return JSONResponse(_entry_dict(entry))
