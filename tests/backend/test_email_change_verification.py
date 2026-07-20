"""Verified email change (SR: AUTH-01).

A self-service email change is staged and only promoted once the recipient
proves control of the new address via a one-time token. Committing unverified
would let a caller claim an address they don't own, which SSO JIT auto-link
then trusts — the takeover primitive this closes. Runs against testcontainer
Postgres.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from graphql import GraphQLError
from sqlalchemy import delete, select

from src.auth.account import service as account_service
from src.auth.account.service import change_email, confirm_email_change
from src.db.helpers import run_db
from src.db.models import User
from src.shared.passwords import hash_password


@pytest.fixture(autouse=True)
def _mailer(monkeypatch):
    """Satisfy the SMTP precondition and capture the token instead of sending."""
    sent: dict[str, str] = {}

    def _capture(to_email: str, token: str) -> bool:
        sent["to"] = to_email
        sent["token"] = token
        return True

    monkeypatch.setenv("SMTP_HOST", "smtp.test")
    monkeypatch.setattr(account_service, "_send_email_verification", _capture)
    return sent


def _seed(user_id: str, **fields) -> None:
    attrs = {
        "id": user_id,
        "username": user_id,
        "email": f"{user_id}@example.com",
        "password_hash": hash_password("correct-horse"),
        "status": "active",
        **fields,
    }

    async def _q(session):
        session.add(User(**attrs))

    run_db(_q)


def _row(user_id: str) -> User:
    async def _q(session):
        return (await session.execute(select(User).where(User.id == user_id))).scalar_one()

    return run_db(_q)


def _cleanup(prefix: str) -> None:
    async def _q(session):
        await session.execute(delete(User).where(User.id.like(f"{prefix}%")))

    run_db(_q)


def _ctx(user_id: str) -> dict:
    return {"user_id": user_id, "role": "member"}


def test_change_is_staged_not_committed(_mailer):
    uid = f"emv-stage-{uuid4().hex[:8]}"
    _seed(uid)
    try:
        change_email(email="New@Example.com", current_password="correct-horse", info_context=_ctx(uid))
        row = _row(uid)
        assert row.email == f"{uid}@example.com"          # unchanged
        assert row.pending_email == "new@example.com"     # staged, normalized
        assert row.pending_email_token_hash is not None
        assert _mailer["to"] == "new@example.com"
    finally:
        _cleanup(uid)


def test_confirm_promotes_and_clears(_mailer):
    uid = f"emv-ok-{uuid4().hex[:8]}"
    _seed(uid)
    try:
        change_email(email="new@example.com", current_password="correct-horse", info_context=_ctx(uid))
        confirm_email_change(token=_mailer["token"])
        row = _row(uid)
        assert row.email == "new@example.com"
        assert row.pending_email is None
        assert row.pending_email_token_hash is None
        assert row.pending_email_expires_at is None
    finally:
        _cleanup(uid)


def test_confirm_rejects_unknown_token(_mailer):
    with pytest.raises(GraphQLError) as exc:
        confirm_email_change(token="not-a-real-token")
    assert exc.value.extensions["code"] == "NOT_FOUND"


def test_confirm_rejects_expired_token(_mailer):
    uid = f"emv-exp-{uuid4().hex[:8]}"
    _seed(uid)
    try:
        change_email(email="new@example.com", current_password="correct-horse", info_context=_ctx(uid))
        token = _mailer["token"]

        # Backdate the expiry so the token is stale.
        async def _expire(session):
            u = (await session.execute(select(User).where(User.id == uid))).scalar_one()
            u.pending_email_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)

        run_db(_expire)

        with pytest.raises(GraphQLError) as exc:
            confirm_email_change(token=token)
        assert exc.value.extensions["code"] == "NOT_FOUND"
        assert _row(uid).email == f"{uid}@example.com"  # never promoted
    finally:
        _cleanup(uid)


def test_request_blocks_email_already_in_use(_mailer):
    owner = f"emv-owner-{uuid4().hex[:8]}"
    mover = f"emv-mover-{uuid4().hex[:8]}"
    _seed(owner, email="taken@example.com")
    _seed(mover)
    try:
        with pytest.raises(GraphQLError) as exc:
            change_email(email="taken@example.com", current_password="correct-horse", info_context=_ctx(mover))
        assert exc.value.extensions["code"] == "CONFLICT"
    finally:
        _cleanup("emv-owner-")
        _cleanup("emv-mover-")


def test_confirm_rechecks_uniqueness_at_promotion(_mailer):
    mover = f"emv-mover-{uuid4().hex[:8]}"
    other = f"emv-other-{uuid4().hex[:8]}"
    _seed(mover)
    _seed(other)
    try:
        # Free at request time, so the change is staged.
        change_email(email="contested@example.com", current_password="correct-horse", info_context=_ctx(mover))
        token = _mailer["token"]

        # Another account grabs the address before the mover confirms.
        async def _grab(session):
            u = (await session.execute(select(User).where(User.id == other))).scalar_one()
            u.email = "contested@example.com"

        run_db(_grab)

        with pytest.raises(GraphQLError) as exc:
            confirm_email_change(token=token)
        assert exc.value.extensions["code"] == "CONFLICT"
        assert _row(mover).email == f"{mover}@example.com"  # not promoted
    finally:
        _cleanup("emv-mover-")
        _cleanup("emv-other-")


def test_change_requires_smtp(monkeypatch):
    uid = f"emv-nosmtp-{uuid4().hex[:8]}"
    _seed(uid)
    monkeypatch.delenv("SMTP_HOST", raising=False)
    try:
        with pytest.raises(GraphQLError) as exc:
            change_email(email="new@example.com", current_password="correct-horse", info_context=_ctx(uid))
        assert exc.value.extensions["code"] == "FAILED_PRECONDITION"
    finally:
        _cleanup(uid)
