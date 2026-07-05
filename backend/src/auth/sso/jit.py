"""JIT (just-in-time) lookup or create for SSO logins."""
from __future__ import annotations

import secrets
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import SsoConfig, User


class AccountConflict(RuntimeError):
    """Raised when an email matches a user already linked to a different SSO subject."""


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
        return row

    row = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if row is not None:
        if row.sso_subject is not None:
            raise AccountConflict("Email already linked to a different SSO identity.")
        row.sso_subject = subject
        row.sso_protocol = protocol
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
