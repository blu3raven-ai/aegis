"""SAML login / ACS / metadata / SLO routes."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from sqlalchemy import select

from src.auth.authentication.cookies import SESSION_COOKIE_NAME, clear_auth_cookies
from src.auth.authentication.login_router import _issue_session
from src.auth.authentication.session import DEFAULT_TTL_SECONDS, SessionService
from src.auth.federation.jit import AccountConflict, jit_or_lookup
from src.auth.federation.saml import (
    SamlSloDispatch,
    build_authn_request,
    build_idp_logout_response,
    build_sp_logout_request,
    parse_idp_logout_request,
    sp_metadata_xml,
    verify_idp_logout_response,
    verify_saml_response,
)
from src.auth.federation.state import decode_saml_slo_state, encode_saml_slo_state
from src.db.helpers import run_db
from src.db.models import SsoConfig, User, UserSession

saml_router = APIRouter(prefix="/auth/sso/saml", tags=["auth"])

_SAML_SLO_STATE_TTL_SECONDS = 300


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


def _dispatch_response(dispatch: SamlSloDispatch) -> Response:
    """Render a SAML dispatch as either a 302 redirect or an auto-submit form."""
    if dispatch.method == "GET":
        return RedirectResponse(dispatch.url, status_code=302)
    return HTMLResponse(content=dispatch.body)


def _saml_session_lookup(session_id: str):
    """Lookup (session, user) for a SAML-authenticated session.

    Returns (None, None) when the session is unknown, expired, revoked, or
    the user is not SAML-authenticated. Synchronous because the SLO routes
    run under FastAPI's sync threadpool via `run_db`.
    """

    async def _do(session) -> tuple[UserSession | None, User | None]:
        svc = SessionService(db=session, ttl_seconds=DEFAULT_TTL_SECONDS)
        sess = await svc.lookup(session_id)
        if sess is None:
            return None, None
        user = sess.user
        if user is None or user.sso_protocol != "saml" or not user.sso_subject:
            return None, None
        return sess, user

    return run_db(_do)


async def _revoke_user_saml_sessions(session, user_id: str) -> int:
    svc = SessionService(db=session, ttl_seconds=DEFAULT_TTL_SECONDS)
    return await svc.revoke_all_for_user(
        user_id=user_id, except_session_id=None, reason="saml_slo",
    )


@saml_router.api_route("/slo", methods=["GET", "POST"])
async def saml_slo(request: Request) -> Response:
    """Dual-purpose SAML SLO endpoint.

    Per the SAML 2.0 binding profile a single SingleLogoutService URL handles
    both inbound IdP-initiated `LogoutRequest` messages and the IdP's
    `LogoutResponse` callback for SP-initiated SLO. The endpoint dispatches
    on whichever parameter is present:

      * `SAMLRequest`  → IdP-initiated: kill the matching Aegis session,
        return a signed `LogoutResponse` bound per the inbound binding.
      * `SAMLResponse` → SP-initiated callback: verify the response, clear
        the Aegis cookie, redirect to `/login`.

    Accepts both HTTP-Redirect (GET) and HTTP-POST bindings on both paths.
    """
    cfg = run_db(_load_config)
    if cfg is None:
        return Response(status_code=404)

    if request.method == "GET":
        params = request.query_params
        saml_request = params.get("SAMLRequest", "")
        saml_response = params.get("SAMLResponse", "")
        relay_state = params.get("RelayState")
        sigalg = params.get("SigAlg")
        signature = params.get("Signature")
        binding = BINDING_HTTP_REDIRECT
    else:
        form = await request.form()
        saml_request = str(form.get("SAMLRequest") or "")
        saml_response = str(form.get("SAMLResponse") or "")
        rs = form.get("RelayState")
        relay_state = str(rs) if rs is not None else None
        sigalg = None
        signature = None
        binding = BINDING_HTTP_POST

    if saml_response:
        return _handle_idp_logout_response(
            request, cfg, saml_response, relay_state or "", binding,
        )
    if saml_request:
        return await _handle_idp_logout_request(
            request, cfg, saml_request, relay_state, binding, sigalg, signature,
        )
    return Response(status_code=400)


async def _handle_idp_logout_request(
    request: Request,
    cfg: SsoConfig,
    saml_request: str,
    relay_state: str | None,
    binding: str,
    sigalg: str | None,
    signature: str | None,
) -> Response:
    try:
        parsed = parse_idp_logout_request(
            cfg, _origin(request), saml_request, binding,
            relay_state=relay_state, sigalg=sigalg, signature=signature,
        )
    except Exception:
        return Response(status_code=400)

    async def _kill(session) -> bool:
        user = (
            await session.execute(
                select(User).where(
                    User.sso_subject == parsed.name_id,
                    User.sso_protocol == "saml",
                )
            )
        ).scalar_one_or_none()
        if user is None:
            return False
        revoked = await _revoke_user_saml_sessions(session, user.id)
        return revoked > 0

    success = run_db(_kill)
    dispatch = build_idp_logout_response(
        cfg, _origin(request), parsed.raw, binding,
        success=success, relay_state=relay_state,
    )
    return _dispatch_response(dispatch)


def _handle_idp_logout_response(
    request: Request,
    cfg: SsoConfig,
    saml_response: str,
    relay_state: str,
    binding: str,
) -> Response:
    if not relay_state:
        return _inline_clear_and_redirect()
    try:
        in_response_to = verify_idp_logout_response(
            cfg, _origin(request), saml_response, binding,
        )
        state = decode_saml_slo_state(relay_state, max_age=_SAML_SLO_STATE_TTL_SECONDS)
    except Exception:
        return _inline_clear_and_redirect()

    if state.get("request_id") != in_response_to:
        return _inline_clear_and_redirect()

    session_id = state.get("session_id") or ""
    if session_id:
        async def _kill(session) -> None:
            svc = SessionService(db=session, ttl_seconds=DEFAULT_TTL_SECONDS)
            await svc.revoke(session_id, reason="saml_slo")

        run_db(_kill)

    return _inline_clear_and_redirect()


@saml_router.get("/slo/initiate")
def saml_slo_initiate(request: Request) -> Response:
    """SP-initiated logout entrypoint.

    Idempotent — when SAML isn't configured or the caller's session isn't
    SAML-authenticated, fall through to the inline cookie-clear logout path
    so callers can use this URL unconditionally as a logout link.
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME, "")
    cfg = run_db(_load_config)
    if cfg is None or not session_id:
        return _inline_clear_and_redirect()

    sess, user = _saml_session_lookup(session_id)
    if sess is None or user is None or not user.sso_subject:
        return _inline_clear_and_redirect()

    request_id = f"_aegis-slo-{secrets.token_urlsafe(16)}"
    try:
        relay = encode_saml_slo_state(request_id=request_id, session_id=sess.id)
        dispatch = build_sp_logout_request(
            cfg, _origin(request), user.sso_subject,
            request_id=request_id, relay_state=relay,
        )
    except Exception:
        return _inline_clear_and_redirect()

    return _dispatch_response(dispatch)


def _inline_clear_and_redirect() -> Response:
    """Build a /login redirect that also clears the auth cookies.

    Shared by `/slo/initiate` (when SAML SLO isn't applicable) and the
    SP-initiated callback path so the user always lands on the same
    destination the inline `/auth/logout` would produce.
    """
    response = RedirectResponse("/login", status_code=302)
    clear_auth_cookies(response)
    return response

