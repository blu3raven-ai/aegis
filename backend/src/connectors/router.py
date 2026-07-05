"""REST endpoints for the connectors kernel catalog."""
from __future__ import annotations

from fastapi import APIRouter

from src.connectors.catalog import serialize_catalog

router = APIRouter(prefix="/api/v1/connectors", tags=["connectors"])


@router.get("", summary="List all registered connectors")
def list_connectors() -> dict:
    """Return the catalog payload as `{connectors: [...], total: N}`."""
    payload = serialize_catalog()
    return {"connectors": payload, "total": len(payload)}
