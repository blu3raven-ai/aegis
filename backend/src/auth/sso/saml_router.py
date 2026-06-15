"""SAML login / ACS / metadata routes."""
from __future__ import annotations

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from src.auth.login_router import _issue_session
from src.auth.sso.jit import AccountConflict, jit_or_lookup
from src.auth.sso.saml import build_authn_request, sp_metadata_xml, verify_saml_response
from src.db.helpers import run_db
from src.db.models import SsoConfig

saml_router = APIRouter(prefix="/auth/sso/saml", tags=["sso-saml"])


def _origin(request: Request) -> str:
    scheme = request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"


async def _load_config(session) -> SsoConfig | None:
    row = (await session.execute(select(SsoConfig).where(SsoConfig.id == 1))).scalar_one_or_none()
    if row is None or not row.enabled or row.protocol != "saml":
        return None
    if not row.saml_metadata_xml or not row.saml_sp_private_key_enc:
        return None
    return row


@saml_router.get("/login")
def saml_login(request: Request) -> Response:
    cfg = run_db(_load_config)
    if cfg is None:
        return RedirectResponse("/login?error=sso_disabled", status_code=302)
    location, _req_id = build_authn_request(cfg, _origin(request))
    return RedirectResponse(location, status_code=302)


@saml_router.post("/acs")
def saml_acs(
    request: Request,
    SAMLResponse: str = Form(...),
) -> Response:
    cfg = run_db(_load_config)
    if cfg is None:
        return RedirectResponse("/login?error=sso_disabled", status_code=302)
    try:
        identity = verify_saml_response(cfg, _origin(request), SAMLResponse)
    except Exception:
        return RedirectResponse("/login?error=sso_failed", status_code=302)

    redirect = RedirectResponse("/", status_code=302)

    async def _do(session) -> bool:
        try:
            user = await jit_or_lookup(
                session,
                subject=identity.subject,
                email=identity.email,
                protocol="saml",
            )
        except AccountConflict:
            return False
        await _issue_session(user=user, response=redirect, request=request, db=session)
        return True

    ok = run_db(_do)
    if not ok:
        return RedirectResponse("/login?error=sso_conflict", status_code=302)
    return redirect


@saml_router.get("/metadata")
def saml_metadata(request: Request) -> Response:
    cfg = run_db(_load_config)
    if cfg is None:
        return Response(status_code=404)
    xml = sp_metadata_xml(cfg, _origin(request))
    return Response(content=xml, media_type="application/samlmetadata+xml")
