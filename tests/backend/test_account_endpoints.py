"""Tests for /api/v1/account/{email,totp/{enroll,verify,disable}}."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from src.db.helpers import run_db
from src.db.models import User


def _get_user(user_id: str) -> User | None:
    async def _q(session):
        return await session.get(User, user_id)
    return run_db(_q)


def test_post_totp_enroll_returns_qr_and_secret():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="acct-totp-1")

    resp = client.post("/api/v1/auth/totp/enroll")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["qrDataUrl"].startswith("data:image/png;base64,")
    assert len(body["secret"]) >= 16  # 20 raw bytes → 32 base32 chars

    # Server should NOT persist or enable TOTP yet.
    user = _get_user("acct-totp-1")
    assert user.totp_secret is None
    assert user.totp_enabled is False


def test_post_totp_enroll_requires_auth():
    from fastapi.testclient import TestClient
    from src.main import app

    resp = TestClient(app).post("/api/v1/auth/totp/enroll")
    assert resp.status_code == 401


def test_post_totp_verify_with_correct_code_enables_totp():
    from conftest import make_authed_client
    from src.graphql.account_resolvers import _generate_totp_secret, _stash_pending_totp
    from src.shared.totp import _totp_code_at

    user_id = "acct-totp-2"
    secret = _generate_totp_secret()
    _stash_pending_totp(user_id, secret)

    code = _totp_code_at(secret, int(time.time()) // 30)
    resp = make_authed_client(role="admin", user_id=user_id).post(
        "/api/v1/auth/totp/verify", json={"code": code}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True}

    user = _get_user(user_id)
    assert user.totp_enabled is True
    assert user.totp_secret  # encrypted secret persisted
    assert user.totp_secret != secret  # stored encrypted, not raw


def test_post_totp_verify_with_wrong_code_keeps_disabled():
    from conftest import make_authed_client
    from src.graphql.account_resolvers import _generate_totp_secret, _stash_pending_totp

    user_id = "acct-totp-3"
    _stash_pending_totp(user_id, _generate_totp_secret())

    resp = make_authed_client(role="admin", user_id=user_id).post(
        "/api/v1/auth/totp/verify", json={"code": "000000"}
    )
    assert resp.status_code == 400

    user = _get_user(user_id)
    assert user.totp_enabled is False
    assert user.totp_secret is None


def test_post_totp_verify_rejects_non_numeric_code():
    from conftest import make_authed_client
    from src.graphql.account_resolvers import _generate_totp_secret, _stash_pending_totp

    user_id = "acct-totp-4"
    _stash_pending_totp(user_id, _generate_totp_secret())

    resp = make_authed_client(role="admin", user_id=user_id).post(
        "/api/v1/auth/totp/verify", json={"code": "abcdef"}
    )
    assert resp.status_code == 400


def test_post_totp_verify_without_enrollment_returns_400():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="acct-totp-5")

    resp = client.post("/api/v1/auth/totp/verify", json={"code": "123456"})
    assert resp.status_code == 400


def test_post_totp_verify_requires_auth():
    from fastapi.testclient import TestClient
    from src.main import app

    resp = TestClient(app).post("/api/v1/auth/totp/verify", json={"code": "123456"})
    assert resp.status_code == 401


def test_post_totp_disable_clears_secret_and_disables():
    from conftest import make_authed_client
    from src.shared.encryption import encrypt_string

    user_id = "acct-totp-6"

    async def _seed(session):
        user = await session.get(User, user_id)
        if user is not None:
            user.totp_secret = encrypt_string("JBSWY3DPEHPK3PXP")  # arbitrary base32
            user.totp_enabled = True

    client = make_authed_client(role="admin", user_id=user_id)
    run_db(_seed)
    assert _get_user(user_id).totp_enabled is True

    resp = client.post("/api/v1/auth/totp/disable")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}

    user = _get_user(user_id)
    assert user.totp_enabled is False
    assert user.totp_secret is None


def test_post_totp_disable_requires_auth():
    from fastapi.testclient import TestClient
    from src.main import app

    resp = TestClient(app).post("/api/v1/auth/totp/disable")
    assert resp.status_code == 401


def test_patch_email_updates_user_email():
    from conftest import make_authed_client
    user_id = "acct-email-1"
    client = make_authed_client(role="admin", user_id=user_id)

    resp = client.patch("/api/v1/auth/email", json={"email": "New.Addr@Example.com"})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True}

    user = _get_user(user_id)
    assert user.email == "new.addr@example.com"


def test_patch_email_allows_clearing_with_empty_string():
    from conftest import make_authed_client
    user_id = "acct-email-2"
    client = make_authed_client(role="admin", user_id=user_id)

    resp = client.patch("/api/v1/auth/email", json={"email": ""})
    assert resp.status_code == 200, resp.text

    user = _get_user(user_id)
    assert user.email == ""


def test_patch_email_conflict_when_in_use_by_other_user():
    from conftest import make_authed_client

    other_user_id = "acct-email-other"
    other_email = "taken@example.com"

    async def _seed(session):
        existing = await session.get(User, other_user_id)
        if existing is None:
            now = datetime.now(timezone.utc)
            session.add(User(
                id=other_user_id,
                username="taken-user",
                email=other_email,
                password_hash="",
                role_id="role_admin",
                status="active",
                created_at=now,
                updated_at=now,
            ))

    run_db(_seed)

    client = make_authed_client(role="admin", user_id="acct-email-3")
    resp = client.patch("/api/v1/auth/email", json={"email": other_email})
    assert resp.status_code == 409, resp.text
    assert "already in use" in resp.json()["detail"].lower()


def test_patch_email_requires_auth():
    from fastapi.testclient import TestClient
    from src.main import app

    resp = TestClient(app).patch("/api/v1/auth/email", json={"email": "x@example.com"})
    assert resp.status_code == 401


def test_patch_email_rejects_api_key_identity():
    """API-key callers must not change the recovery email — email is a
    password-reset channel, so allowing a machine identity to swap it would
    let a leaked key escalate to a full account takeover via password reset.

    Today SessionAuthMiddleware blocks API-key Bearer requests against
    /api/v1/settings/account/* at the gate, but the router-layer dependency is the
    defense-in-depth that has to survive future routing changes — so the
    contract is asserted directly against the dependency.
    """
    import types

    import pytest
    from fastapi import HTTPException

    from src.authz.enforcement import require_caller_identity

    request = types.SimpleNamespace(
        state=types.SimpleNamespace(
            user_sub="api_key:42",
            user_role="viewer",
            user_role_id=None,
        )
    )
    assert getattr(request.state, "session", None) is None

    with pytest.raises(HTTPException) as excinfo:
        require_caller_identity(request)
    assert excinfo.value.status_code == 403


def test_post_totp_enroll_rejects_api_key_identity():
    """API-key callers must not reach TOTP self-service — the enroll response
    carries a fresh secret in plaintext, which is meaningful only to a human
    setting up their authenticator. Machine identities have no use for it and
    granting them access expands the blast radius of a leaked key.

    Today SessionAuthMiddleware blocks API-key Bearer requests against
    /api/v1/settings/account/* at the gate, but the router-layer dependency is the
    defense-in-depth that has to survive future routing changes — so the
    contract is asserted directly against the dependency.
    """
    import types

    import pytest
    from fastapi import HTTPException

    from src.authz.enforcement import require_caller_identity

    # Shape of request.state after API-key auth (see credentials/middleware.py):
    # user_sub is set to api_key:<id> but SessionAuthMiddleware never populated
    # request.state.session — that's the discriminator the dependency uses.
    request = types.SimpleNamespace(
        state=types.SimpleNamespace(
            user_sub="api_key:42",
            user_role="viewer",
            user_role_id=None,
        )
    )
    assert getattr(request.state, "session", None) is None

    with pytest.raises(HTTPException) as excinfo:
        require_caller_identity(request)
    assert excinfo.value.status_code == 403
