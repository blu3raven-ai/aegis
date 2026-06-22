"""Unit tests for SSO just-in-time provisioning.

Exercises gaps not covered by tests/backend/test_sso_jit.py:
OIDC protocol path, protocol isolation, default-role injection,
and behavior when an already-linked user is deprovisioned.

Runs against the testcontainer Postgres provided by src/tests/conftest.py.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

from src.auth.federation.jit import AccountConflict, jit_or_lookup
from src.db.helpers import run_db
from src.db.models import Role, SsoConfig, User


def _reset_sso_cfg(default_role_id: str | None = None) -> None:
    from sqlalchemy import select

    async def _seed(session):
        row = (await session.execute(select(SsoConfig).where(SsoConfig.id == 1))).scalar_one_or_none()
        if row is None:
            row = SsoConfig(id=1)
            session.add(row)
        row.default_role_id = default_role_id

    run_db(_seed)


def _ensure_role(role_id: str, name: str = "Test Role") -> None:
    async def _seed(session):
        existing = await session.get(Role, role_id)
        if existing is None:
            session.add(Role(id=role_id, name=name, description="", permissions={}, protected=False))

    run_db(_seed)


def _cleanup_users(prefix: str) -> None:
    from sqlalchemy import delete

    async def _del(session):
        await session.execute(delete(User).where(User.id.like(f"{prefix}%")))

    run_db(_del)


def test_jit_oidc_creates_new_user_with_sso_protocol_oidc():
    _reset_sso_cfg()
    uniq = uuid4().hex[:8]
    email = f"oidc-{uniq}@example.com"
    subject = f"oidc-sub-{uniq}"

    async def _act(session):
        return await jit_or_lookup(session, subject=subject, email=email, protocol="oidc")

    try:
        user = run_db(_act)
        assert user.email == email
        assert user.sso_subject == subject
        assert user.sso_protocol == "oidc"
        assert user.status == "active"
    finally:
        _cleanup_users("sso-")


def test_jit_assigns_default_role_when_configured():
    role_id = f"role_jit_test_{uuid4().hex[:6]}"
    _ensure_role(role_id, "JIT Default")
    _reset_sso_cfg(default_role_id=role_id)
    uniq = uuid4().hex[:8]

    async def _act(session):
        return await jit_or_lookup(
            session,
            subject=f"with-role-{uniq}",
            email=f"with-role-{uniq}@example.com",
            protocol="saml",
        )

    try:
        user = run_db(_act)
        assert user.role_id == role_id
    finally:
        _cleanup_users("sso-")
        # Reset default_role_id so other tests don't inherit a now-deleted role.
        _reset_sso_cfg(default_role_id=None)


def test_jit_lookup_by_subject_returns_linked_user_regardless_of_email():
    """Subject is the primary identifier — email at the IdP can drift over time.

    A user whose linked email has changed at the IdP should still be located
    by subject, not forced through the email-attach branch.
    """
    _reset_sso_cfg()
    uniq = uuid4().hex[:8]
    subject = f"drift-sub-{uniq}"

    async def _seed(session):
        session.add(User(
            id=f"jit-drift-{uniq}",
            username=f"u-drift-{uniq}",
            email=f"old-{uniq}@example.com",
            password_hash="",
            status="active",
            sso_subject=subject,
            sso_protocol="saml",
        ))

    run_db(_seed)

    async def _act(session):
        return await jit_or_lookup(
            session,
            subject=subject,
            email=f"new-{uniq}@example.com",
            protocol="saml",
        )

    try:
        user = run_db(_act)
        assert user.id == f"jit-drift-{uniq}"
        # Email is not auto-synced from the assertion — locks current behavior.
        assert user.email == f"old-{uniq}@example.com"
    finally:
        _cleanup_users(f"jit-drift-{uniq}")


def test_jit_reactivates_deprovisioned_user_and_writes_audit_event():
    """A deprovisioned user signing in via SSO is flipped back to active
    and an explicit `user.reactivated` audit event is written.

    Reactivation is intentional: an IdP can re-add a user to the SSO group
    after a previous deprovisioning. The audit log makes it traceable.
    The scim_managed flag is NOT touched on reactivation.
    """
    from sqlalchemy import delete, select as _select
    from src.db.models import AuditEvent

    _reset_sso_cfg()
    uniq = uuid4().hex[:8]
    subject = f"dep-sub-{uniq}"
    user_id = f"jit-dep-{uniq}"

    async def _seed(session):
        session.add(User(
            id=user_id,
            username=f"u-dep-{uniq}",
            email=f"dep-{uniq}@example.com",
            password_hash="",
            status="deprovisioned",
            sso_subject=subject,
            sso_protocol="saml",
            scim_managed=True,
        ))

    run_db(_seed)

    async def _act(session):
        return await jit_or_lookup(
            session,
            subject=subject,
            email=f"dep-{uniq}@example.com",
            protocol="saml",
        )

    async def _events(session):
        rows = (
            await session.execute(
                _select(AuditEvent)
                .where(AuditEvent.action == "user.reactivated")
                .where(AuditEvent.resource_id == user_id)
            )
        ).scalars().all()
        return [(r.action, r.metadata_json, r.actor_user_id, r.resource_id) for r in rows]

    async def _cleanup_events(session):
        await session.execute(
            delete(AuditEvent).where(AuditEvent.resource_id == user_id)
        )

    try:
        user = run_db(_act)
        assert user.id == user_id
        assert user.status == "active"
        # scim_managed is preserved across JIT reactivation — the flag tracks
        # provisioning origin, not lifecycle state.
        assert user.scim_managed is True

        events = run_db(_events)
        assert len(events) == 1, events
        action, metadata, actor_user_id, resource_id = events[0]
        assert action == "user.reactivated"
        assert metadata == {"trigger": "jit_sign_in"}
        assert actor_user_id == "system:sso_jit"
        assert resource_id == user_id
    finally:
        run_db(_cleanup_events)
        _cleanup_users(user_id)


def test_jit_account_conflict_carries_message():
    _reset_sso_cfg()
    uniq = uuid4().hex[:8]
    email = f"conflict-{uniq}@example.com"

    async def _seed(session):
        session.add(User(
            id=f"jit-conf-{uniq}",
            username=f"u-conf-{uniq}",
            email=email,
            password_hash="",
            status="active",
            sso_subject=f"existing-{uniq}",
            sso_protocol="saml",
        ))

    run_db(_seed)

    async def _act(session):
        return await jit_or_lookup(
            session,
            subject=f"new-{uniq}",
            email=email,
            protocol="saml",
        )

    try:
        with pytest.raises(AccountConflict) as exc:
            run_db(_act)
        assert "different SSO identity" in str(exc.value)
    finally:
        _cleanup_users(f"jit-conf-{uniq}")


def test_jit_attaches_to_local_user_without_sso():
    """A pre-existing local user (no sso_subject) should attach on first SSO login."""
    _reset_sso_cfg()
    uniq = uuid4().hex[:8]
    email = f"local-{uniq}@example.com"

    async def _seed(session):
        session.add(User(
            id=f"jit-local-{uniq}",
            username=f"u-local-{uniq}",
            email=email,
            password_hash="hashed-local-password",
            status="active",
        ))

    run_db(_seed)

    async def _act(session):
        return await jit_or_lookup(
            session,
            subject=f"new-sso-{uniq}",
            email=email,
            protocol="oidc",
        )

    try:
        user = run_db(_act)
        assert user.id == f"jit-local-{uniq}"
        assert user.sso_subject == f"new-sso-{uniq}"
        assert user.sso_protocol == "oidc"
        # Local password is preserved — JIT only adds SSO linkage.
        assert user.password_hash == "hashed-local-password"
    finally:
        _cleanup_users(f"jit-local-{uniq}")
