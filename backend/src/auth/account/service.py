"""Account service layer — profile, email, avatar, TOTP, notification prefs.

Backs the REST endpoints under /api/v1/settings/account/* (see the sibling
``*_router.py`` files in this package). Despite the legacy Strawberry
``@input`` decorators on a few request-body types, no GraphQL field uses
this module — the account surface is REST-only.
"""
from __future__ import annotations

import base64
import io
import secrets as _secrets
import time
from typing import Optional
from urllib.parse import quote

import strawberry
from graphql import GraphQLError

from src.audit_log.recorder import ActorInfo, RequestContext, get_recorder
from src.graphql.resolver_utils import raise_bad_input
from src.db.helpers import run_db
from src.db.models import User, UserPreferences
from src.shared.encryption import encrypt_string
from src.shared.passwords import verify_password
from src.shared.totp import verify_totp
from sqlalchemy import func, select


_MAX_AVATAR_DATA_URL_BYTES = 200 * 1024
_ALLOWED_AVATAR_MIME = ("image/png", "image/jpeg", "image/gif", "image/webp")
_TOTP_ENROLL_TTL_SECONDS = 10 * 60

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


def _validate_avatar_data_url(data_url: str) -> None:
    if len(data_url) > _MAX_AVATAR_DATA_URL_BYTES:
        raise_bad_input("Avatar too large.")
    if not data_url.startswith("data:"):
        raise_bad_input("Avatar must be a data URL.")
    header, _, _ = data_url.partition(",")
    if ";base64" not in header:
        raise_bad_input("Avatar must be base64-encoded.")
    mime = header.removeprefix("data:").split(";", 1)[0].strip().lower()
    if mime not in _ALLOWED_AVATAR_MIME:
        raise_bad_input("Unsupported image type.")


def _generate_totp_secret() -> str:
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
    import qrcode

    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('ascii')}"


async def _get_or_create_prefs(session, user_id: str) -> UserPreferences:
    row = await session.get(UserPreferences, user_id)
    if row is None:
        row = UserPreferences(user_id=user_id)
        session.add(row)
        await session.flush()
    return row


def _fire_audit(action: str, user_id: str, role: str) -> None:
    try:
        get_recorder().record(
            action=action,
            resource_type="account",
            actor=ActorInfo(user_id=user_id, role=role),
            request=RequestContext(method="MUTATION", path="/graphql"),
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Strawberry types
# ---------------------------------------------------------------------------

@strawberry.type
class AccountProfile:
    theme: str
    timezone: str


@strawberry.type
class AccountNotifications:
    assignments: bool
    mentions: bool
    kev: bool
    weekly_digest: bool
    marketing: bool


@strawberry.type
class TotpEnrollResult:
    qr_data_url: str
    secret: str


@strawberry.type
class AccountMutationResult:
    ok: bool


# ---------------------------------------------------------------------------
# Query resolvers
# ---------------------------------------------------------------------------

def account_profile(*, info_context: dict) -> AccountProfile:
    user_id = info_context["user_id"]

    async def _q(session):
        return await _get_or_create_prefs(session, user_id)

    row = run_db(_q)
    return AccountProfile(theme=row.theme, timezone=row.timezone)


def account_notifications(*, info_context: dict) -> AccountNotifications:
    user_id = info_context["user_id"]

    async def _q(session):
        return await _get_or_create_prefs(session, user_id)

    row = run_db(_q)
    return AccountNotifications(
        assignments=row.notif_assignments,
        mentions=row.notif_mentions,
        kev=row.notif_kev,
        weekly_digest=row.notif_weekly_digest,
        marketing=row.notif_marketing,
    )


# ---------------------------------------------------------------------------
# Mutation resolvers
# ---------------------------------------------------------------------------

def change_email(
    *, email: str, current_password: str, info_context: dict
) -> AccountMutationResult:
    user_id = info_context["user_id"]
    new_email = email.strip().lower() if email else ""

    async def _q(session):
        user = await session.get(User, user_id)
        if user is None:
            raise GraphQLError("User not found.", extensions={"code": "NOT_FOUND"})
        # Re-authenticate before re-routing the recovery email: a hijacked or
        # unattended session must not silently change it. Password-backed users
        # prove the current password; SSO users without a local password must
        # prove a TOTP code instead. SSO users with neither factor are blocked.
        if user.password_hash:
            if not verify_password(current_password, user.password_hash):
                raise GraphQLError(
                    "Current password is incorrect.", extensions={"code": "FORBIDDEN"}
                )
        elif user.totp_enabled and user.totp_secret:
            if not verify_totp(user.totp_secret, current_password):
                raise GraphQLError(
                    "TOTP code is incorrect.", extensions={"code": "FORBIDDEN"}
                )
        else:
            raise GraphQLError(
                "Email changes for SSO accounts require TOTP to be enabled.",
                extensions={"code": "FORBIDDEN"},
            )
        if new_email:
            existing = await session.execute(
                select(User).where(func.lower(User.email) == new_email, User.id != user_id)
            )
            if existing.scalar_one_or_none() is not None:
                raise GraphQLError("Email already in use.", extensions={"code": "CONFLICT"})
        user.email = new_email

    run_db(_q)
    _fire_audit("account.email.updated", user_id, info_context.get("role", ""))
    return AccountMutationResult(ok=True)


def set_avatar(*, avatar_url: str, info_context: dict) -> AccountMutationResult:
    user_id = info_context["user_id"]
    _validate_avatar_data_url(avatar_url)

    async def _q(session):
        user = await session.get(User, user_id)
        if user is None:
            raise GraphQLError("User not found.", extensions={"code": "NOT_FOUND"})
        user.avatar_url = avatar_url

    run_db(_q)
    return AccountMutationResult(ok=True)


def clear_avatar(*, info_context: dict) -> AccountMutationResult:
    user_id = info_context["user_id"]

    async def _q(session):
        user = await session.get(User, user_id)
        if user is None:
            raise GraphQLError("User not found.", extensions={"code": "NOT_FOUND"})
        user.avatar_url = None

    run_db(_q)
    return AccountMutationResult(ok=True)


def begin_totp_enrollment(*, info_context: dict) -> TotpEnrollResult:
    user_id = info_context["user_id"]
    request = info_context.get("request")
    user_obj = getattr(request.state, "user", None) if request else None
    username = getattr(user_obj, "username", "") or ""

    secret = _generate_totp_secret()
    uri = _build_otpauth_uri(secret, username=username)
    qr_data_url = _render_qr_data_url(uri)
    _stash_pending_totp(user_id, secret)

    return TotpEnrollResult(qr_data_url=qr_data_url, secret=secret)


def verify_totp_enrollment(*, code: str, info_context: dict) -> AccountMutationResult:
    user_id = info_context["user_id"]
    code = code.strip()
    if len(code) != 6 or not code.isdigit():
        raise_bad_input("Code must be 6 digits.")

    secret = _pop_pending_totp(user_id)
    if secret is None:
        raise_bad_input("Enrollment expired. Start setup again.")
    if not verify_totp(secret, code):
        _stash_pending_totp(user_id, secret)
        raise_bad_input("Invalid code.")

    encrypted = encrypt_string(secret)

    async def _q(session):
        user = await session.get(User, user_id)
        if user is None:
            raise GraphQLError("User not found.", extensions={"code": "NOT_FOUND"})
        user.totp_secret = encrypted
        user.totp_enabled = True

    run_db(_q)
    _fire_audit("account.totp.enabled", user_id, info_context.get("role", ""))
    return AccountMutationResult(ok=True)


def disable_totp(*, code: str, info_context: dict) -> AccountMutationResult:
    user_id = info_context["user_id"]

    async def _q(session):
        user = await session.get(User, user_id)
        if user is None:
            raise GraphQLError("User not found.", extensions={"code": "NOT_FOUND"})
        # Removing the second factor is high-value: require a current code so a
        # hijacked or unattended session can't strip 2FA on its own.
        if user.totp_enabled and user.totp_secret:
            if not verify_totp(user.totp_secret, code):
                raise GraphQLError(
                    "Verification code is incorrect.", extensions={"code": "FORBIDDEN"}
                )
        user.totp_secret = None
        user.totp_enabled = False

    run_db(_q)
    # Only drop the pending-enrollment scratch after the disable actually commits.
    _pending_totp.pop(user_id, None)
    _fire_audit("account.totp.disabled", user_id, info_context.get("role", ""))
    return AccountMutationResult(ok=True)


def update_account_profile(
    *,
    theme: Optional[str],
    timezone: Optional[str],
    info_context: dict,
) -> AccountProfile:
    user_id = info_context["user_id"]

    async def _q(session):
        row = await _get_or_create_prefs(session, user_id)
        if theme is not None:
            row.theme = theme
        if timezone is not None:
            row.timezone = timezone
        return row

    row = run_db(_q)
    return AccountProfile(theme=row.theme, timezone=row.timezone)


def update_account_notifications(
    *,
    assignments: Optional[bool],
    mentions: Optional[bool],
    kev: Optional[bool],
    weekly_digest: Optional[bool],
    marketing: Optional[bool],
    info_context: dict,
) -> AccountNotifications:
    user_id = info_context["user_id"]

    async def _q(session):
        row = await _get_or_create_prefs(session, user_id)
        if assignments is not None:
            row.notif_assignments = assignments
        if mentions is not None:
            row.notif_mentions = mentions
        if kev is not None:
            row.notif_kev = kev
        if weekly_digest is not None:
            row.notif_weekly_digest = weekly_digest
        if marketing is not None:
            row.notif_marketing = marketing
        return row

    row = run_db(_q)
    return AccountNotifications(
        assignments=row.notif_assignments,
        mentions=row.notif_mentions,
        kev=row.notif_kev,
        weekly_digest=row.notif_weekly_digest,
        marketing=row.notif_marketing,
    )
