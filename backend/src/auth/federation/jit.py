"""JIT (just-in-time) lookup or create for SSO logins."""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import AuditEvent, SsoConfig, User


class AccountConflict(RuntimeError):
    """Raised when an email matches a user already linked to a different SSO subject."""


def _record_reactivation(session: AsyncSession, user: User) -> None:
    """Write a `user.reactivated` audit event via the current session.

    Using session.add() rather than AuditRecorder.record() because the
    recorder spawns its own run_db() call which would deadlock when invoked
    from inside an already-running run_db() coroutine.
    """
    now = datetime.now(timezone.utc)
    session.add(AuditEvent(
        action="user.reactivated",
        resource_type="user",
        resource_id=user.id,
        actor_user_id="system:sso_jit",
        actor_username=user.username,
        actor_email=user.email,
        actor_role="system",
        metadata_json={"trigger": "jit_sign_in"},
        created_at=now,
        occurred_at=now,
    ))


async def _maybe_reactivate(session: AsyncSession, user: User) -> None:
    if user.status != "deprovisioned":
        return
    user.status = "active"
    _record_reactivation(session, user)


async def jit_or_lookup(
    session: AsyncSession,
    subject: str,
    email: str,
    protocol: Literal["saml", "oidc"],
) -> User:
    row = (
        await session.execute(
            select(User).where(User.sso_subject == subject).where(User.sso_protocol == protocol)
        )
    ).scalar_one_or_none()
    if row is not None:
        await _maybe_reactivate(session, row)
        return row

    row = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if row is not None:
        if row.sso_subject is not None:
            raise AccountConflict("Email already linked to a different SSO identity.")
        row.sso_subject = subject
        row.sso_protocol = protocol
        await _maybe_reactivate(session, row)
        return row

    cfg = (await session.execute(select(SsoConfig).where(SsoConfig.id == 1))).scalar_one()
    user = User(
        id=f"sso-{secrets.token_urlsafe(12)}",
        username=email,
        email=email,
        password_hash="",
        role_id=cfg.default_role_id,
        status="active",
        sso_subject=subject,
        sso_protocol=protocol,
    )
    session.add(user)
    await session.flush()
    return user
