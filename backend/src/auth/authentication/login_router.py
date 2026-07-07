"""Cookie-based login endpoints — destination for PR 3 BFF migration.

Three endpoints:
  POST /auth/login         — email + password → either session OR pending-mfa
  POST /auth/login/verify  — pending-mfa token + TOTP code → session
  POST /auth/logout        — revoke session, clear cookies (idempotent)

DORMANT in PR 1: registered on the app, but the BFF still mints JWTs for
all existing traffic. PR 3 will delete the BFF and the frontend will start
hitting these directly.
"""
from __future__ import annotations

import ipaddress
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import func as sql_func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit_log.recorder import ActorInfo, AuditRecorder, RequestContext
from src.auth.authentication.cookies import (
    MFA_PENDING_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    clear_auth_cookies,
    clear_mfa_pending_cookie,
    set_csrf_cookie,
    set_mfa_pending_cookie,
    set_session_cookie,
)
from src.auth.authentication.csrf import compute_csrf_token
from src.auth.authentication.rate_limit import RateLimitService
from src.auth.authentication.session import DEFAULT_TTL_SECONDS, SessionService
from src.db.models import User
from src.authz.roles.service import role_kind_from_id
from src.shared.config import get_session_secret
from src.shared.passwords import hash_password, verify_password
from src.shared.encryption import DecryptionError
from src.shared.totp import verify_totp

_logger = logging.getLogger(__name__)

PENDING_MFA_TTL_SECONDS = 5 * 60

# A pending-MFA token is burned after this many wrong codes so a stolen
# password can't be paired with an unbounded second-factor guessing spree
# against a single long-lived token.
MAX_MFA_ATTEMPTS = 5

# In-memory pending-MFA store. PR 1 — for prod, swap to Postgres or a signed
# stateless token in PR 3 if multi-worker survival becomes a requirement.
_pending_mfa: dict[str, dict] = {}

login_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

_audit = AuditRecorder()


_DUMMY_PASSWORD_HASH: str = hash_password("\x00" * 16)



async def _get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an AsyncSession per request.

    Imports `async_session_factory` lazily so that tests can set DATABASE_URL
    before the engine module is first evaluated. The session factory is shared
    within a process (same pool), but each `async with factory()` call gets an
    independent session object.
    """
    from src.db.engine import async_session_factory
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise



async def _rate_limit_ip(request: Request, db: AsyncSession) -> None:
    ip = _client_ip(request) or (request.client.host if request.client else "unknown")
    svc = RateLimitService(db=db)
    allowed = await svc.check_and_record(
        key=f"/api/v1/auth/login:ip:{ip}", limit=5, window_seconds=60
    )
    if not allowed:
        _audit.record(
            action="auth.login.rate_limited",
            resource_type="ip",
            actor=ActorInfo(),
            metadata={"limit_kind": "ip", "ip": ip},
        )
        raise HTTPException(status_code=429, detail="too many login attempts")


async def _rate_limit_user(email: str, db: AsyncSession) -> None:
    svc = RateLimitService(db=db)
    allowed = await svc.check_and_record(
        key=f"/api/v1/auth/login:user:{email.lower()}", limit=10, window_seconds=3600
    )
    if not allowed:
        _audit.record(
            action="auth.login.rate_limited",
            resource_type="user",
            actor=ActorInfo(email=email),
            metadata={"limit_kind": "user", "email": email},
        )
        raise HTTPException(status_code=429, detail="too many login attempts")



class LoginRequest(BaseModel):
    identifier: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1)


class LoginVerifyRequest(BaseModel):
    # The pending-MFA token now rides in an HttpOnly cookie, not the body.
    code: str = Field(min_length=6, max_length=6)



@login_router.post("/login")
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(_get_db),
):
    await _rate_limit_ip(request, db)
    await _rate_limit_user(payload.identifier, db)
    await db.commit()

    identifier = payload.identifier.strip().lower()
    # Try username first
    result = await db.execute(
        select(User).where(sql_func.lower(User.username) == identifier)
    )
    user = result.scalar_one_or_none()
    if user is None:
        # Fall back to email lookup
        result = await db.execute(
            select(User).where(sql_func.lower(User.email) == identifier)
        )
        user = result.scalar_one_or_none()

    ctx = _req_context(request)

    password_hash = user.password_hash if user is not None else _DUMMY_PASSWORD_HASH
    password_ok = verify_password(payload.password, password_hash)

    if user is None or not password_ok:
        actor_email = payload.identifier
        _audit.record(
            action="auth.login.failure",
            resource_type="user",
            actor=ActorInfo(email=actor_email),
            request=ctx,
            metadata={"reason": "invalid_credentials"},
        )
        raise HTTPException(status_code=401, detail="invalid credentials")

    if user.status not in ("active", "pending"):
        _audit.record(
            action="auth.login.failure",
            resource_type="user",
            actor=ActorInfo(email=user.email or payload.identifier),
            request=ctx,
            metadata={"reason": "account_disabled"},
        )
        raise HTTPException(status_code=401, detail="Account is disabled.")

    if user.totp_enabled and user.totp_secret:
        pending_token = secrets.token_urlsafe(32)
        _pending_mfa[pending_token] = {
            "user_id": user.id,
            "expires_at": datetime.now(timezone.utc) + timedelta(seconds=PENDING_MFA_TTL_SECONDS),
            "attempts": 0,
        }
        # Hand the token back as an HttpOnly cookie, never in the body — page JS
        # (and any XSS) must not be able to read or exfiltrate it.
        set_mfa_pending_cookie(response, token=pending_token, max_age=PENDING_MFA_TTL_SECONDS)
        return {"mfa_required": True}

    return await _issue_session(user=user, response=response, request=request, db=db)


@login_router.post("/login/verify")
async def login_verify(
    payload: LoginVerifyRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(_get_db),
):
    # IP rate-limit runs first so a cookie-less brute force of this endpoint is
    # still throttled, then the token check.
    await _rate_limit_ip(request, db)
    pending_token = request.cookies.get(MFA_PENDING_COOKIE_NAME)
    if not pending_token:
        await db.commit()
        raise HTTPException(status_code=401, detail="invalid credentials")
    await _rate_limit_user(pending_token, db)
    await db.commit()

    pending = _pending_mfa.get(pending_token)
    if pending is None or pending["expires_at"] < datetime.now(timezone.utc):
        _pending_mfa.pop(pending_token, None)
        clear_mfa_pending_cookie(response)
        raise HTTPException(status_code=401, detail="invalid credentials")

    result = await db.execute(select(User).where(User.id == pending["user_id"]))
    user = result.scalar_one_or_none()
    if user is None:
        _pending_mfa.pop(pending_token, None)
        clear_mfa_pending_cookie(response)
        raise HTTPException(status_code=401, detail="invalid credentials")

    try:
        totp_ok = verify_totp(user.totp_secret or "", payload.code)
    except DecryptionError:
        # The stored 2FA secret can't be decrypted (encryption key changed) — do
        # NOT treat this as a wrong code (which would lock the user out with a
        # misleading message). Surface a clear, distinct server error instead.
        _logger.error("verify_totp: stored TOTP secret could not be decrypted for user %s", user.id)
        raise HTTPException(
            status_code=503,
            detail="Two-factor verification is temporarily unavailable. Contact your administrator.",
        ) from None
    if not totp_ok:
        # Burn the token after too many wrong codes so the attacker must
        # re-authenticate with the password to obtain a fresh one.
        pending["attempts"] = pending.get("attempts", 0) + 1
        if pending["attempts"] >= MAX_MFA_ATTEMPTS:
            _pending_mfa.pop(pending_token, None)
            clear_mfa_pending_cookie(response)
        raise HTTPException(status_code=401, detail="invalid credentials")

    _pending_mfa.pop(pending_token, None)
    clear_mfa_pending_cookie(response)

    return await _issue_session(user=user, response=response, request=request, db=db)


@login_router.get("/me")
async def me(request: Request):
    """Return the currently authenticated user from the session.

    The SessionAuthMiddleware has already validated the session cookie and
    attached request.state.user before this endpoint is reached.
    """
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="unauthorized")
    return {
        "user": {
            "id": str(user.id),
            "username": getattr(user, "username", None),
            "email": user.email,
            "role": getattr(user, "role", None),
            "roleId": getattr(user, "role_id", None),
            "status": getattr(user, "status", "active"),
            "sessionVersion": getattr(user, "session_version", 1),
            "totpEnabled": getattr(user, "totp_enabled", False),
            "avatarUrl": getattr(user, "avatar_url", None),
        },
    }


@login_router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(_get_db),
):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    # When the active session is SAML-authenticated AND the IdP advertises a
    # SingleLogoutService, hand off to the SP-initiated SLO flow instead of
    # clearing the cookie inline. Closes the shared-workstation gap where the
    # next user could otherwise hit SSO and walk back in as the previous one.
    if session_id and await _should_use_saml_slo(session_id, request, db):
        return RedirectResponse(
            "/auth/sso/saml/slo/initiate", status_code=303,
        )

    if session_id is not None:
        svc = SessionService(db=db, ttl_seconds=DEFAULT_TTL_SECONDS)
        revoked = await svc.revoke(session_id, reason="logout")
        if revoked:
            _audit.record(
                action="auth.logout",
                resource_type="session",
                resource_id=session_id,
                request=_req_context(request),
            )
        await db.commit()

    clear_auth_cookies(response)
    return {"ok": True}


async def _should_use_saml_slo(
    session_id: str, request: Request, db: AsyncSession,
) -> bool:
    """Return True when this session should hand off to SP-initiated SLO.

    Failing closed — any error (no config row, missing keys, IdP metadata
    that lacks an SLO endpoint, decryption failure) falls back to the inline
    cookie-clear path so logout always succeeds even when SAML is half-set-up.
    """
    try:
        from src.auth.federation.saml import idp_supports_slo
        from src.db.models import SsoConfig, UserSession

        sess = (
            await db.execute(
                select(UserSession).where(
                    UserSession.id == session_id,
                    UserSession.revoked_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        if sess is None or sess.user is None:
            return False
        user = sess.user
        if user.sso_protocol != "saml" or not user.sso_subject:
            return False

        cfg = (
            await db.execute(select(SsoConfig).where(SsoConfig.id == 1))
        ).scalar_one_or_none()
        if cfg is None or not cfg.enabled or cfg.protocol != "saml":
            return False
        if not cfg.saml_metadata_xml or not cfg.saml_sp_private_key_enc:
            return False

        scheme = request.url.scheme
        host = request.headers.get("host") or request.url.netloc
        origin = f"{scheme}://{host}"
        return idp_supports_slo(cfg, origin)
    except Exception:
        return False



def _client_ip(request: Request) -> str | None:
    """Return the client IP only if it's a valid address; else None.

    TestClient and reverse proxies without X-Forwarded-For may send a
    non-IP hostname. INET columns in Postgres reject those — None is safer.
    """
    host = request.client.host if request.client else None
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return None


def _req_context(request: Request) -> RequestContext:
    return RequestContext(
        method=request.method,
        path=request.url.path,
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )


async def _issue_session(
    *,
    user: User,
    response: Response,
    request: Request,
    db: AsyncSession,
) -> dict:
    svc = SessionService(db=db, ttl_seconds=DEFAULT_TTL_SECONDS)
    session = await svc.create(
        user_id=user.id,
        user_agent=request.headers.get("user-agent"),
        ip_address=_client_ip(request),
    )

    csrf = compute_csrf_token(session.id, secret=get_session_secret())
    set_session_cookie(response, session_id=session.id, max_age=DEFAULT_TTL_SECONDS)
    set_csrf_cookie(response, csrf_token=csrf, max_age=DEFAULT_TTL_SECONDS)

    _audit.record(
        action="auth.login.success",
        resource_type="user",
        resource_id=str(user.id),
        actor=ActorInfo(user_id=str(user.id), email=user.email),
        request=_req_context(request),
        metadata={"session_id": session.id},
    )
    await db.commit()

    return {
        "user": {
            "id": str(user.id),
            "email": user.email,
            "role": role_kind_from_id(user.role_id),
            "status": user.status or "active",
        },
    }
