"""OIDC login + callback routes."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from src.auth.authentication.login_router import _issue_session
from src.auth.federation.jit import AccountConflict, jit_or_lookup
from src.auth.federation.oidc import authorize_url, exchange_code
from src.auth.federation.state import decode_state, encode_state
from src.db.helpers import run_db
from src.db.models import SsoConfig

oidc_router = APIRouter(prefix="/auth/sso/oidc", tags=["auth"])

_STATE_COOKIE = "__Host-sso-oidc-state"
_STATE_TTL_SECONDS = 300


def _origin(request: Request) -> str:
    scheme = request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"


def _redirect_uri(request: Request) -> str:
    return f"{_origin(request)}/auth/sso/oidc/callback"


async def _load_config(session) -> SsoConfig | None:
    row = (await session.execute(select(SsoConfig).where(SsoConfig.id == 1))).scalar_one_or_none()
    if row is None or not row.enabled or row.protocol != "oidc":
        return None
    if not row.oidc_discovery_url or not row.oidc_client_id or not row.oidc_client_secret_enc:
        return None
    return row


@oidc_router.get("/login")
async def oidc_login(request: Request) -> Response:
    cfg = run_db(_load_config)
    if cfg is None:
        return RedirectResponse("/login?error=sso_disabled", status_code=302)
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    try:
        url = await authorize_url(cfg, _redirect_uri(request), state, nonce)
    except Exception:
        return RedirectResponse("/login?error=sso_failed", status_code=302)
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(
        _STATE_COOKIE,
        encode_state(state=state, nonce=nonce),
        max_age=_STATE_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/auth/sso/oidc/callback",
    )
    return resp


@oidc_router.get("/callback")
async def oidc_callback(request: Request, code: str = "", state: str = "") -> Response:
    cfg = run_db(_load_config)
    if cfg is None:
        return RedirectResponse("/login?error=sso_disabled", status_code=302)
    token = request.cookies.get(_STATE_COOKIE)
    if not token or not code or not state:
        return RedirectResponse("/login?error=sso_failed", status_code=302)
    try:
        decoded = decode_state(token, max_age=_STATE_TTL_SECONDS)
    except Exception:
        return RedirectResponse("/login?error=sso_failed", status_code=302)
    if decoded.get("state") != state:
        return RedirectResponse("/login?error=sso_failed", status_code=302)

    try:
        identity = await exchange_code(cfg, _redirect_uri(request), code, decoded["nonce"])
    except Exception:
        return RedirectResponse("/login?error=sso_failed", status_code=302)

    redirect = RedirectResponse("/", status_code=302)
    redirect.delete_cookie(_STATE_COOKIE, path="/auth/sso/oidc/callback")

    async def _do(session) -> bool:
        try:
            user = await jit_or_lookup(
                session,
                subject=identity.subject,
                email=identity.email,
                protocol="oidc",
                email_verified=identity.email_verified,
            )
        except AccountConflict:
            return False
        await _issue_session(user=user, response=redirect, request=request, db=session)
        return True

    ok = run_db(_do)
    if not ok:
        return RedirectResponse("/login?error=sso_conflict", status_code=302)
    return redirect
