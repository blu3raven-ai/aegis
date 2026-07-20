"""Re-authentication guards on sensitive self-service account mutations.

Auth-audit finding 4.2: changing the recovery email or removing the second
factor must require proof of identity, so a hijacked or unattended session
can't do either silently. Runs against the testcontainer Postgres.
"""
from __future__ import annotations

import time
from uuid import uuid4

import pytest
from graphql import GraphQLError

from src.auth.account.service import change_email, disable_totp
from src.db.helpers import run_db
from src.db.models import User
from src.shared.encryption import encrypt_string
from src.shared.passwords import hash_password
from src.shared.totp import _totp_code_at


def _cleanup(prefix: str) -> None:
    from sqlalchemy import delete

    async def _del(session):
        await session.execute(delete(User).where(User.id.like(f"{prefix}%")))

    run_db(_del)


def _seed_user(user_id: str, **fields) -> None:
    attrs = {
        "id": user_id,
        "username": user_id,
        "email": f"{user_id}@example.com",
        "password_hash": "",
        "status": "active",
        **fields,
    }

    async def _seed(session):
        session.add(User(**attrs))

    run_db(_seed)


def _email_of(user_id: str) -> str:
    from sqlalchemy import select

    async def _q(session):
        return (await session.execute(select(User.email).where(User.id == user_id))).scalar_one()

    return run_db(_q)


def _totp_enabled_of(user_id: str) -> bool:
    from sqlalchemy import select

    async def _q(session):
        return (await session.execute(select(User.totp_enabled).where(User.id == user_id))).scalar_one()

    return run_db(_q)


def _ctx(user_id: str) -> dict:
    return {"user_id": user_id, "role": "member"}


# --- change_email ----------------------------------------------------------

def test_change_email_requires_correct_password_for_password_users(monkeypatch):
    uid = f"reauth-em-{uuid4().hex[:8]}"
    _seed_user(uid, password_hash=hash_password("correct-horse"))
    # A change is now staged for verification, not committed, so mock the mailer
    # and satisfy the SMTP precondition.
    monkeypatch.setenv("SMTP_HOST", "smtp.test")
    monkeypatch.setattr(
        "src.auth.account.service._send_email_verification", lambda *a, **k: True
    )
    try:
        with pytest.raises(GraphQLError) as exc:
            change_email(email="new@example.com", current_password="wrong", info_context=_ctx(uid))
        assert exc.value.extensions["code"] == "FORBIDDEN"
        assert _email_of(uid) == f"{uid}@example.com"  # unchanged

        # Correct re-auth stages the change but must NOT commit it until verified.
        change_email(email="new@example.com", current_password="correct-horse", info_context=_ctx(uid))
        assert _email_of(uid) == f"{uid}@example.com"  # still the old address
    finally:
        _cleanup(uid)


def test_change_email_requires_totp_for_passwordless_sso_users():
    uid = f"reauth-sso-{uuid4().hex[:8]}"
    _seed_user(uid, password_hash="", sso_subject=f"sub-{uid}", sso_protocol="oidc")
    try:
        with pytest.raises(GraphQLError) as exc:
            change_email(email="moved@example.com", current_password="", info_context=_ctx(uid))
        assert exc.value.extensions["code"] == "FORBIDDEN"
        assert _email_of(uid) != "moved@example.com"
    finally:
        _cleanup(uid)


# --- disable_totp ----------------------------------------------------------

def test_disable_totp_requires_a_valid_current_code():
    uid = f"reauth-totp-{uuid4().hex[:8]}"
    secret = "JBSWY3DPEHPK3PXP"  # RFC 6238 test-ish base32 secret
    _seed_user(uid, totp_enabled=True, totp_secret=encrypt_string(secret))
    try:
        with pytest.raises(GraphQLError) as exc:
            disable_totp(code="000000", info_context=_ctx(uid))
        assert exc.value.extensions["code"] == "FORBIDDEN"
        assert _totp_enabled_of(uid) is True  # still enabled

        valid = _totp_code_at(secret, int(time.time()) // 30)
        disable_totp(code=valid, info_context=_ctx(uid))
        assert _totp_enabled_of(uid) is False
    finally:
        _cleanup(uid)
