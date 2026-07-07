"""JIT (just-in-time) lookup or create for SSO logins."""
from __future__ import annotations

import secrets
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import SsoConfig, User


class AccountConflict(RuntimeError):
    """Raised when an email matches a user already linked to a different SSO subject."""


class AccountDeprovisioned(AccountConflict):
    """Raised when a deprovisioned user attempts to sign in via SSO.

    Subclasses AccountConflict so the existing SSO-router handlers reject the
    login; a deprovisioned account must be reactivated by an explicit admin
    action, never silently by the next SSO sign-in.
    """


def _reject_if_deprovisioned(user: User) -> None:
    # An audit event is deliberately NOT written here: it would share the login
    # transaction, which the raised exception rolls back. The SSO router logs the
    # rejected sign-in instead.
    if user.status == "deprovisioned":
        raise AccountDeprovisioned("Account is deprovisioned; an administrator must reactivate it.")


async def _is_privileged_account(session: AsyncSession, user: User) -> bool:
    """True if the account's role can administer users.

    Checked through the permissions layer rather than a role-name comparison,
    so any role that grants user administration — built-in or custom — is
    protected from silent SSO auto-linking. The role is loaded on the caller's
    own session (not a fresh connection) so this stays inside the login
    transaction.
    """
    from src.authz.permissions.catalog import MANAGE_USERS
    from src.authz.permissions.service import resolve_role_permissions
    from src.db.models import Role

    if not user.role_id:
        return False
    role = await session.get(Role, user.role_id)
    if role is None:
        return False
    return MANAGE_USERS in resolve_role_permissions({"permissions": role.permissions})


async def jit_or_lookup(
    session: AsyncSession,
    subject: str,
    email: str,
    protocol: Literal["saml", "oidc"],
    *,
    email_verified: bool,
) -> User:
    """Resolve the local User for an SSO login, provisioning one if needed.

    A returning user is always matched by their stable `subject`. Falling back
    to matching an existing account by `email` — which attaches this SSO
    identity to that account — is only safe when the provider verified the
    email; otherwise an IdP that lets a caller set an arbitrary address could
    be used to take over a pre-existing (e.g. local admin) account.
    """
    normalized_email = email.strip().lower()

    row = (
        await session.execute(
            select(User).where(User.sso_subject == subject).where(User.sso_protocol == protocol)
        )
    ).scalar_one_or_none()
    if row is not None:
        _reject_if_deprovisioned(row)
        return row

    # Case-insensitive match: an IdP that varies the email casing must not be
    # able to mint a second, takeover-shaped row alongside the real account.
    row = (
        await session.execute(
            select(User).where(func.lower(User.email) == normalized_email)
        )
    ).scalar_one_or_none()
    if row is not None:
        if row.sso_subject is not None:
            raise AccountConflict("Email already linked to a different SSO identity.")
        if not email_verified:
            raise AccountConflict("Email is not provider-verified; cannot link to an existing account.")
        # A privileged account is the highest-value takeover target, and the
        # verified-email signal is only as trustworthy as the IdP behind it.
        # Linking SSO onto such an account must be a deliberate step taken from
        # account settings by someone already authenticated to it, never an
        # implicit consequence of a first SSO sign-in.
        if await _is_privileged_account(session, row):
            raise AccountConflict(
                "Cannot auto-link an SSO identity onto a privileged account; "
                "link it from account settings instead."
            )
        row.sso_subject = subject
        row.sso_protocol = protocol
        _reject_if_deprovisioned(row)
        return row

    cfg = (await session.execute(select(SsoConfig).where(SsoConfig.id == 1))).scalar_one()
    user = User(
        id=f"sso-{secrets.token_urlsafe(12)}",
        username=normalized_email,
        email=normalized_email,
        password_hash="",
        role_id=cfg.default_role_id,
        status="active",
        sso_subject=subject,
        sso_protocol=protocol,
    )
    session.add(user)
    await session.flush()
    return user
