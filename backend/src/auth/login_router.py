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
from pydantic import BaseModel, Field
from sqlalchemy import func as sql_func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit_log.recorder import ActorInfo, AuditRecorder, RequestContext
from src.auth.cookies import (
    SESSION_COOKIE_NAME,
    clear_auth_cookies,
    set_csrf_cookie,
    set_session_cookie,
)
from src.auth.csrf import compute_csrf_token
from src.auth.rate_limit import RateLimitService
from src.auth.session import DEFAULT_TTL_SECONDS, SessionService
from src.db.models import User
from src.shared.config import get_session_secret
from src.shared.passwords import hash_password, verify_password
from src.shared.totp import verify_totp

_logger = logging.getLogger(__name__)

PENDING_MFA_TTL_SECONDS = 5 * 60

# In-memory pending-MFA store. PR 1 — for prod, swap to Postgres or a signed
# stateless token in PR 3 if multi-worker survival becomes a requirement.
_pending_mfa: dict[str, dict] = {}

login_router = APIRouter(prefix="/auth", tags=["auth"])

_audit = AuditRecorder()


# Pre-computed dummy hash for timing equalisation — see _DUMMY_PASSWORD_HASH below.
# Computed once at import so the scrypt cost is paid once, not per request.
_DUMMY_PASSWORD_HASH: str = hash_password("\x00" * 16)


# ── DB session dependency ─────────────────────────────────────────────────────

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


# ── Rate-limiting helpers ─────────────────────────────────────────────────────

async def _rate_limit_ip(request: Request, db: AsyncSession) -> None:
    ip = _client_ip(request) or (request.client.host if request.client else "unknown")
    svc = RateLimitService(db=db)
    allowed = await svc.check_and_record(
        key=f"/auth/login:ip:{ip}", limit=5, window_seconds=60
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
        key=f"/auth/login:user:{email.lower()}", limit=10, window_seconds=3600
    )
    if not allowed:
        _audit.record(
            action="auth.login.rate_limited",
            resource_type="user",
            actor=ActorInfo(email=email),
            metadata={"limit_kind": "user", "email": email},
        )
        raise HTTPException(status_code=429, detail="too many login attempts")


# ── Request models ────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    identifier: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1)


class LoginVerifyRequest(BaseModel):
    pending_token: str = Field(min_length=1)
    code: str = Field(min_length=6, max_length=6)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@login_router.post("/login")
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(_get_db),
):
    # Rate-limit checks flush counters — must commit regardless of auth outcome.
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

    # Always run scrypt — defeats user-enumeration via response timing.
    # When the user doesn't exist we verify against a pre-computed dummy hash
    # so the timing is indistinguishable from a real user with a wrong password.
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
        # Identical message for unknown user vs wrong password — no enumeration
        raise HTTPException(status_code=401, detail="invalid credentials")

    if user.totp_enabled and user.totp_secret:
        pending_token = secrets.token_urlsafe(32)
        _pending_mfa[pending_token] = {
            "user_id": user.id,
            "expires_at": datetime.now(timezone.utc) + timedelta(seconds=PENDING_MFA_TTL_SECONDS),
        }
        return {"mfa_required": True, "pending_token": pending_token}

    return await _issue_session(user=user, response=response, request=request, db=db)


@login_router.post("/login/verify")
async def login_verify(
    payload: LoginVerifyRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(_get_db),
):
    pending = _pending_mfa.get(payload.pending_token)
    if pending is None or pending["expires_at"] < datetime.now(timezone.utc):
        # Pop expired entry to avoid accumulation
        _pending_mfa.pop(payload.pending_token, None)
        raise HTTPException(status_code=401, detail="invalid credentials")

    result = await db.execute(select(User).where(User.id == pending["user_id"]))
    user = result.scalar_one_or_none()
    if user is None:
        _pending_mfa.pop(payload.pending_token, None)
        raise HTTPException(status_code=401, detail="invalid credentials")

    if not verify_totp(user.totp_secret or "", payload.code):
        raise HTTPException(status_code=401, detail="invalid credentials")

    # Consume — single-use even on success
    _pending_mfa.pop(payload.pending_token, None)

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
            "mfaEnabled": getattr(user, "totp_enabled", False),
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


# ── Private helpers ───────────────────────────────────────────────────────────

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
            "role": user.role,
            "status": user.status or "active",
        },
    }
