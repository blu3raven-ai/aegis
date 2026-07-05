"""Public read-only branding metadata for the unauthenticated login surface."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import OrgSettings

branding_router = APIRouter(prefix="/api/v1/branding", tags=["branding"])


@branding_router.get("")
def get_public_branding() -> JSONResponse:
    async def _q(session):
        row = (await session.execute(select(OrgSettings).where(OrgSettings.id == 1))).scalar_one_or_none()
        # NULL row OR NULL name = vendor branding (clients render the default
        # Aegis 3-line identity). The vendor literal never appears in this
        # response payload — clients own the fallback string.
        if row is None:
            return {"name": None, "logoDataUrl": None}
        return {"name": row.name, "logoDataUrl": row.logo_data_url}

    body = run_db(_q)
    return JSONResponse(body, status_code=200)
