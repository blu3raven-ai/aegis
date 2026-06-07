"""REST endpoints for /api/v1/integrations."""
from __future__ import annotations

from dataclasses import asdict
from fastapi import APIRouter, Request

from src.integrations.catalog import CATALOG
from src.settings.router import require_permission

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


@router.get("/catalog", summary="List all available connector types")
def get_catalog(request: Request) -> dict:
    require_permission(request, "view_settings")
    return {
        "connectors": [asdict(c) for c in CATALOG],
        "total": len(CATALOG),
    }
