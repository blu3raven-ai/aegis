"""Per-user account self-service endpoints (email / avatar / TOTP).

Mounted by `settings.router` so the routes appear under `/api/v1/settings/account/*`.
SessionAuthMiddleware has already attached `request.state.user` (a `User`
SQLAlchemy instance) for the calling user.
"""
from __future__ import annotations

import base64
import io
import secrets as _secrets
import time
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select

from src.db.helpers import run_db
from src.db.models import User
from src.settings.schemas import (
    AvatarChangeRequest,
    EmailChangeRequest,
    TotpEnrollResponse,
    TotpVerifyRequest,
)
from src.shared.encryption import encrypt_string
from src.shared.totp import verify_totp

account_router = APIRouter(prefix="/api/v1/settings/account", tags=["account"])


# ── Limits ────────────────────────────────────────────────────────────────────

# Frontend caps avatar uploads at 100 KB; allow a small headroom for the data
# URL prefix (`data:image/png;base64,`) and base64 expansion.
_MAX_AVATAR_DATA_URL_BYTES = 200 * 1024
_ALLOWED_AVATAR_MIME = ("image/png", "image/jpeg", "image/gif", "image/webp")

# How long an unverified TOTP enrollment lingers in memory before discard.
_TOTP_ENROLL_TTL_SECONDS = 10 * 60


# ── Pending TOTP enrollments ──────────────────────────────────────────────────

# user_id → {"secret": base32, "expires_at": unix_seconds}
# In-memory by design: enrollment is a short-lived setup ceremony. Multi-worker
# survival is not required (the user would just re-scan the QR on the new
# worker), and this avoids round-tripping the unconfirmed secret to the client.
_pending_totp: dict[str, dict] = {}


def _stash_pending_totp(user_id: str, secret: str) -> None:
    _purge_expired_totp()
    _pending_totp[user_id] = {
        "secret": secret,
        "expires_at": time.time() + _TOTP_ENROLL_TTL_SECONDS,
    }


def _pop_pending_totp(user_id: str) -> str | None:
    _purge_expired_totp()
    entry = _pending_totp.pop(user_id, None)
    if entry is None:
        return None
    return entry["secret"]


def _purge_expired_totp() -> None:
    now = time.time()
    expired = [uid for uid, entry in _pending_totp.items() if entry["expires_at"] < now]
    for uid in expired:
        _pending_totp.pop(uid, None)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _api_error(message: str, status_code: int) -> HTTPException:
    return HTTPException(status_code=status_code, detail=message)


def _require_user_id(request: Request) -> str:
    user = getattr(request.state, "user", None)
    if user is None or not getattr(user, "id", None):
        raise _api_error("unauthorized", 401)
    return str(user.id)


def _require_username(request: Request) -> str:
    user = getattr(request.state, "user", None)
    return getattr(user, "username", "") or ""


def _validate_avatar_data_url(data_url: str) -> None:
    if len(data_url) > _MAX_AVATAR_DATA_URL_BYTES:
        raise _api_error("Avatar too large.", 400)
    if not data_url.startswith("data:"):
        raise _api_error("Avatar must be a data URL.", 400)
    # `data:image/png;base64,...` — split at the first comma.
    header, _, _ = data_url.partition(",")
    if ";base64" not in header:
        raise _api_error("Avatar must be base64-encoded.", 400)
    mime = header.removeprefix("data:").split(";", 1)[0].strip().lower()
    if mime not in _ALLOWED_AVATAR_MIME:
        raise _api_error("Unsupported image type.", 400)


def _generate_totp_secret() -> str:
    """20 random bytes, base32-encoded (RFC 6238 recommended length)."""
    return base64.b32encode(_secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _build_otpauth_uri(secret: str, *, username: str) -> str:
    issuer = "Aegis"
    label = quote(f"{issuer}:{username or 'user'}", safe="")
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret}&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits=6&period=30"
    )


def _render_qr_data_url(payload: str) -> str:
    # Imported lazily so test environments without the optional dep can still
    # import this module (e.g. for schema reuse).
    import qrcode

    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('ascii')}"


def _ok() -> JSONResponse:
    return JSONResponse({"ok": True}, status_code=200)


# ── Email ─────────────────────────────────────────────────────────────────────

@account_router.patch("/email")
def change_email(request: Request, body: EmailChangeRequest) -> JSONResponse:
    user_id = _require_user_id(request)
    new_email = (body.email or "").strip().lower() if body.email else ""

    async def _query(session):
        if new_email:
            existing = await session.execute(
                select(User).where(func.lower(User.email) == new_email, User.id != user_id)
            )
            if existing.scalar_one_or_none() is not None:
                raise _api_error("Email already in use.", 409)
        user = await session.get(User, user_id)
        if user is None:
            raise _api_error("User not found.", 404)
        user.email = new_email
        return {"ok": True}

    run_db(_query)
    return _ok()


# ── Avatar ────────────────────────────────────────────────────────────────────

@account_router.post("/avatar")
def set_avatar(request: Request, body: AvatarChangeRequest) -> JSONResponse:
    user_id = _require_user_id(request)
    _validate_avatar_data_url(body.avatarUrl)

    async def _query(session):
        user = await session.get(User, user_id)
        if user is None:
            raise _api_error("User not found.", 404)
        user.avatar_url = body.avatarUrl
        return {"ok": True}

    run_db(_query)
    return _ok()


@account_router.delete("/avatar")
def clear_avatar(request: Request) -> JSONResponse:
    user_id = _require_user_id(request)

    async def _query(session):
        user = await session.get(User, user_id)
        if user is None:
            raise _api_error("User not found.", 404)
        user.avatar_url = None
        return {"ok": True}

    run_db(_query)
    return _ok()


# ── TOTP ──────────────────────────────────────────────────────────────────────

@account_router.post("/totp", response_model=TotpEnrollResponse)
def begin_totp_enrollment(request: Request) -> TotpEnrollResponse:
    user_id = _require_user_id(request)
    username = _require_username(request)

    secret = _generate_totp_secret()
    uri = _build_otpauth_uri(secret, username=username)
    qr_data_url = _render_qr_data_url(uri)
    _stash_pending_totp(user_id, secret)

    return TotpEnrollResponse(qrDataUrl=qr_data_url, secret=secret)


@account_router.post("/totp/verify")
def verify_totp_enrollment(request: Request, body: TotpVerifyRequest) -> JSONResponse:
    user_id = _require_user_id(request)
    code = body.code.strip()
    if len(code) != 6 or not code.isdigit():
        raise _api_error("Code must be 6 digits.", 400)

    secret = _pop_pending_totp(user_id)
    if secret is None:
        raise _api_error("Enrollment expired. Start setup again.", 400)
    if not verify_totp(secret, code):
        # Re-stash so the user can retry without restarting enrollment.
        _stash_pending_totp(user_id, secret)
        raise _api_error("Invalid code.", 400)

    encrypted = encrypt_string(secret)

    async def _query(session):
        user = await session.get(User, user_id)
        if user is None:
            raise _api_error("User not found.", 404)
        user.totp_secret = encrypted
        user.totp_enabled = True
        return {"ok": True}

    run_db(_query)
    return _ok()


@account_router.delete("/totp")
def disable_totp(request: Request) -> JSONResponse:
    user_id = _require_user_id(request)
    _pending_totp.pop(user_id, None)

    async def _query(session):
        user = await session.get(User, user_id)
        if user is None:
            raise _api_error("User not found.", 404)
        user.totp_secret = None
        user.totp_enabled = False
        return {"ok": True}

    run_db(_query)
    return _ok()
