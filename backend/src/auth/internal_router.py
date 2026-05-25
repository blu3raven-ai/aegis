"""Internal auth endpoints for the Next.js frontend (BFF).

System-only endpoints gated by _require_system_caller. Password verification
and TOTP verification happen server-side — hashes and secrets never leave the
backend. All user responses use _safe_user_dict (no passwordHash, no totpSecret).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from src.db.helpers import run_db
from src.db.models import User
from src.shared.encryption import decrypt_string, encrypt_string, is_encrypted
from src.shared.paths import now_iso

internal_auth_router = APIRouter(prefix="/auth/internal", tags=["auth-internal"])


def _require_system_caller(request: Request) -> None:
    """Verify the caller is the system service account (Next.js BFF).

    Only the BFF calls these endpoints using SERVICE_USER = { id: "system", role: "owner" }.
    Block any non-system caller to prevent privilege escalation.
    """
    user_sub = getattr(request.state, "user_sub", None)
    user_role = getattr(request.state, "user_role", None)
    if user_sub != "system" or user_role != "owner":
        raise HTTPException(status_code=403, detail="Forbidden: system-only endpoint")


def _safe_user_dict(user: User) -> dict[str, Any]:
    """Return user dict with sensitive fields stripped — safe for lookup responses.

    Never exposes passwordHash or totpSecret to callers.
    """
    created_iso = (
        user.created_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if user.created_at else now_iso()
    )
    updated_iso = (
        user.updated_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if user.updated_at else created_iso
    )
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email or "",
        "role": user.role or "viewer",
        "roleId": user.role_id,
        "status": user.status or "active",
        "passwordResetRequired": user.password_reset_required or False,
        "mfaEnabled": user.totp_enabled or False,
        "avatarUrl": user.avatar_url or "",
        "sessionVersion": user.session_version or 1,
        "createdAt": created_iso,
        "updatedAt": updated_iso,
    }


class VerifyRequest(BaseModel):
    username: str


@internal_auth_router.post("/lookup")
def lookup_user(body: VerifyRequest, request: Request) -> JSONResponse:
    """Find a user by username or email. Returns safe user data (no password hash or TOTP secret)."""
    _require_system_caller(request)
    identifier = body.username.strip().lower()
    if not identifier:
        return JSONResponse({"user": None})

    async def _query(session):
        # Try username first
        result = await session.execute(
            select(User).where(func.lower(User.username) == identifier)
        )
        user = result.scalars().first()
        if not user:
            # Try email
            result = await session.execute(
                select(User).where(func.lower(User.email) == identifier)
            )
            user = result.scalars().first()
        return _safe_user_dict(user) if user else None

    user = run_db(_query)
    return JSONResponse({"user": user})


class VerifyPasswordRequest(BaseModel):
    username: str
    password: str


@internal_auth_router.post("/verify-password")
def verify_password(body: VerifyPasswordRequest, request: Request) -> JSONResponse:
    """Verify a user's password server-side. Returns safe user data if valid, null if not.

    This keeps password hashes on the backend — the BFF never sees the raw hash.
    """
    _require_system_caller(request)
    import hashlib
    import hmac

    identifier = body.username.strip().lower()
    if not identifier or not body.password:
        return JSONResponse({"user": None, "valid": False})

    async def _query(session):
        # Try username first
        result = await session.execute(
            select(User).where(func.lower(User.username) == identifier)
        )
        user = result.scalars().first()
        if not user:
            # Try email
            result = await session.execute(
                select(User).where(func.lower(User.email) == identifier)
            )
            user = result.scalars().first()
        if not user:
            return None, False

        stored = user.password_hash or ""
        if stored.startswith("scrypt:v1:"):
            parts = stored.split(":")
            if len(parts) != 4:
                return user, False
            salt = bytes.fromhex(parts[2])
            stored_key = bytes.fromhex(parts[3])
            input_key = hashlib.scrypt(body.password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=64)
            match = hmac.compare_digest(input_key, stored_key)
        else:
            # Legacy plaintext — compare and auto-upgrade
            match = hmac.compare_digest(body.password.encode(), stored.encode())
            if match and stored:
                import logging
                import os
                logging.getLogger(__name__).warning(
                    "[security] Auto-upgrading legacy plaintext password to scrypt for user %s",
                    user.username,
                )
                salt = os.urandom(16)
                key = hashlib.scrypt(body.password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=64)
                user.password_hash = f"scrypt:v1:{salt.hex()}:{key.hex()}"
                user.updated_at = datetime.now(timezone.utc)
                await session.flush()

        return user, match

    user, valid = run_db(_query)
    if not user or not valid:
        return JSONResponse({"user": None, "valid": False})
    return JSONResponse({"user": _safe_user_dict(user), "valid": True})


class VerifyTotpRequest(BaseModel):
    userId: str
    code: str


@internal_auth_router.post("/verify-totp")
def verify_totp(body: VerifyTotpRequest, request: Request) -> JSONResponse:
    """Verify a TOTP code server-side. Returns safe user data if valid.

    This keeps TOTP secrets on the backend — the BFF never sees the raw secret.
    """
    _require_system_caller(request)

    async def _query(session):
        user = await session.get(User, body.userId)
        if not user or not user.totp_enabled:
            return None, False

        raw_secret = user.totp_secret
        if not raw_secret:
            return user, False

        # Decrypt TOTP secret if encrypted
        if is_encrypted(raw_secret):
            raw_secret = decrypt_string(raw_secret)
        if not raw_secret:
            return user, False

        # Verify the TOTP code (RFC 6238 / RFC 4226 with SHA-1, 6 digits, 30s period)
        import base64
        import hmac as _hmac
        import struct
        import time

        def _totp_code_at(secret_b32: str, counter: int) -> str:
            key = base64.b32decode(secret_b32, casefold=True)
            msg = struct.pack(">Q", counter)
            h = _hmac.new(key, msg, "sha1").digest()
            offset = h[-1] & 0x0F
            code_int = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
            return str(code_int % 10**6).zfill(6)

        now_counter = int(time.time()) // 30
        valid = any(
            _hmac.compare_digest(body.code, _totp_code_at(raw_secret, now_counter + offset))
            for offset in (-1, 0, 1)  # valid_window=1
        )
        return user, valid

    user, valid = run_db(_query)
    if not user or not valid:
        return JSONResponse({"user": None, "valid": False})
    return JSONResponse({"user": _safe_user_dict(user), "valid": True})


@internal_auth_router.get("/user/{user_id}")
def get_user_by_id(user_id: str, request: Request) -> JSONResponse:
    """Get user data by ID. Returns safe dict (no password hash or TOTP secret)."""
    _require_system_caller(request)
    async def _query(session):
        user = await session.get(User, user_id)
        return _safe_user_dict(user) if user else None

    user = run_db(_query)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return JSONResponse({"user": user})


class UpdateAccountRequest(BaseModel):
    username: str | None = None
    email: str | None = None
    passwordHash: str | None = None
    passwordResetRequired: bool | None = None
    status: str | None = None
    avatarUrl: str | None = Field(None, max_length=200_000)


@internal_auth_router.patch("/user/{user_id}/account")
def update_account(user_id: str, body: UpdateAccountRequest, request: Request) -> JSONResponse:
    """Update a user's own account details."""
    _require_system_caller(request)
    async def _query(session):
        user = await session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        if body.username is not None:
            username = body.username.strip()
            if not username:
                raise HTTPException(status_code=400, detail="Username is required.")
            # Check uniqueness
            result = await session.execute(
                select(User).where(func.lower(User.username) == username.lower(), User.id != user_id)
            )
            if result.scalars().first():
                raise HTTPException(status_code=400, detail="User already exists.")
            user.username = username

        if body.email is not None:
            user.email = body.email.strip()

        if body.passwordHash is not None:
            user.password_hash = body.passwordHash

        if body.passwordResetRequired is not None:
            user.password_reset_required = body.passwordResetRequired

        if body.status is not None:
            user.status = body.status

        if body.avatarUrl is not None:
            _ALLOWED_PREFIXES = ("data:image/png", "data:image/jpeg", "data:image/gif", "data:image/webp")
            if body.avatarUrl and not body.avatarUrl.startswith(_ALLOWED_PREFIXES):
                raise HTTPException(status_code=400, detail="Only PNG, JPEG, GIF, and WebP images are allowed.")
            user.avatar_url = body.avatarUrl or None

        user.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _safe_user_dict(user)

    user = run_db(_query)
    return JSONResponse({"user": user})


class UpdateTotpRequest(BaseModel):
    totpSecret: str | None = None
    totpEnabled: bool


@internal_auth_router.patch("/user/{user_id}/totp")
def update_totp(user_id: str, body: UpdateTotpRequest, request: Request) -> JSONResponse:
    """Update a user's TOTP configuration."""
    _require_system_caller(request)
    async def _query(session):
        user = await session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
        # Encrypt TOTP secret before storing
        user.totp_secret = encrypt_string(body.totpSecret) if body.totpSecret else body.totpSecret
        user.totp_enabled = body.totpEnabled
        user.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _safe_user_dict(user)

    user = run_db(_query)
    return JSONResponse({"user": user})


class MigrateUserRequest(BaseModel):
    username: str
    email: str | None = None
    passwordHash: str


@internal_auth_router.post("/migrate")
def migrate_single_user(body: MigrateUserRequest, request: Request) -> JSONResponse:
    """Create the initial admin user if no users exist (first-run migration)."""
    _require_system_caller(request)
    username = body.username.strip()
    if not username or not body.passwordHash:
        return JSONResponse({"user": None})

    async def _query(session):
        # Only migrate if no users exist
        result = await session.execute(select(User).limit(1))
        if result.scalars().first() is not None:
            return None

        now = datetime.now(timezone.utc)
        import secrets
        user = User(
            id=f"usr_{secrets.token_hex(12)}",
            username=username,
            email=body.email or "",
            password_hash=body.passwordHash,
            role="owner",
            role_id="role_owner",
            status="active",
            password_reset_required=False,
            created_at=now,
            updated_at=now,
        )
        session.add(user)
        await session.flush()
        return _safe_user_dict(user)

    user = run_db(_query)
    return JSONResponse({"user": user})


class AuditEventRequest(BaseModel):
    actorUserId: str | None = None
    actorUsername: str | None = None
    action: str = Field(..., max_length=50)
    target: str | None = Field(None, max_length=512)
    metadata: dict[str, Any] | None = None


@internal_auth_router.post("/audit")
def record_audit_event(body: AuditEventRequest, request: Request) -> JSONResponse:
    """Record an audit event from the frontend."""
    _require_system_caller(request)
    from src.settings.audit import record_event
    record_event(
        action=body.action,
        actor_user_id=body.actorUserId,
        actor_username=body.actorUsername,
        target=body.target,
        metadata=body.metadata,
    )
    return JSONResponse({"ok": True})
