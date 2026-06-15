"""Public SSO availability — used by the login page to gate the SSO button."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import SsoConfig

sso_public_router = APIRouter(prefix="/api/v1/sso", tags=["public-sso"])


@sso_public_router.get("/sso-availability")
def sso_availability() -> JSONResponse:
    async def _q(session):
        row = (await session.execute(select(SsoConfig).where(SsoConfig.id == 1))).scalar_one_or_none()
        if row is None or not row.enabled:
            return {"enabled": False, "protocol": None}
        if row.protocol == "saml":
            if not row.saml_metadata_xml or not row.saml_sp_private_key_enc:
                return {"enabled": False, "protocol": None}
            return {"enabled": True, "protocol": "saml"}
        if row.protocol == "oidc":
            if not row.oidc_discovery_url or not row.oidc_client_id or not row.oidc_client_secret_enc:
                return {"enabled": False, "protocol": None}
            return {"enabled": True, "protocol": "oidc"}
        return {"enabled": False, "protocol": None}

    return JSONResponse(run_db(_q), status_code=200)
