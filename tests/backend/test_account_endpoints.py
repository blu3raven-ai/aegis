"""Tests for /api/v1/settings/account/{email,avatar,totp,totp/verify}."""
from __future__ import annotations

import base64

import pytest

from src.db.helpers import run_db
from src.db.models import User


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_user(user_id: str) -> User | None:
    async def _q(session):
        return await session.get(User, user_id)
    return run_db(_q)


def _make_data_url(mime: str = "image/png", payload: bytes = b"x") -> str:
    return f"data:{mime};base64,{base64.b64encode(payload).decode('ascii')}"


# ── Email ─────────────────────────────────────────────────────────────────────

def test_patch_email_updates_user_row():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="acct-email-1")

    resp = client.patch("/api/v1/settings/account/email", json={"email": "new@example.com"})
    assert resp.status_code == 200, resp.text

    user = _get_user("acct-email-1")
    assert user is not None
    assert user.email == "new@example.com"


def test_patch_email_lowercases_and_strips():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="acct-email-2")

    resp = client.patch("/api/v1/settings/account/email", json={"email": "Mixed.Case@Example.COM"})
    assert resp.status_code == 200
    assert (_get_user("acct-email-2").email or "") == "mixed.case@example.com"


def test_patch_email_null_clears_field():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="acct-email-3")

    resp = client.patch("/api/v1/settings/account/email", json={"email": None})
    assert resp.status_code == 200
    assert _get_user("acct-email-3").email == ""


def test_patch_email_rejects_duplicate():
    from conftest import make_authed_client

    # Seed a second user with the email already taken.
    async def _seed(session):
        existing = await session.get(User, "acct-email-other")
        if existing is None:
            session.add(User(
                id="acct-email-other",
                username="other-user",
                email="taken@example.com",
                role="viewer",
                status="active",
            ))
    run_db(_seed)

    client = make_authed_client(role="admin", user_id="acct-email-dup")
    resp = client.patch("/api/v1/settings/account/email", json={"email": "taken@example.com"})
    assert resp.status_code == 409


def test_patch_email_rejects_invalid_format():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="acct-email-bad")

    resp = client.patch("/api/v1/settings/account/email", json={"email": "not-an-email"})
    assert resp.status_code == 422


# ── Avatar ────────────────────────────────────────────────────────────────────

def test_post_avatar_stores_data_url():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="acct-av-1")

    data_url = _make_data_url("image/png", b"\x89PNG")
    resp = client.post("/api/v1/settings/account/avatar", json={"avatarUrl": data_url})
    assert resp.status_code == 200, resp.text

    assert _get_user("acct-av-1").avatar_url == data_url


def test_post_avatar_rejects_non_data_url():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="acct-av-2")

    resp = client.post(
        "/api/v1/settings/account/avatar", json={"avatarUrl": "https://evil.example/x.png"}
    )
    assert resp.status_code == 400


def test_post_avatar_rejects_oversize():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="acct-av-3")

    huge = _make_data_url("image/png", b"x" * (300 * 1024))
    resp = client.post("/api/v1/settings/account/avatar", json={"avatarUrl": huge})
    assert resp.status_code == 400


def test_post_avatar_rejects_unsupported_mime():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="acct-av-4")

    bad_mime = _make_data_url("application/pdf", b"\x25PDF")
    resp = client.post("/api/v1/settings/account/avatar", json={"avatarUrl": bad_mime})
    assert resp.status_code == 400


def test_delete_avatar_clears_field():
    """Single HTTP call: seed avatar directly, then DELETE.

    Pre-existing asyncpg+TestClient cross-loop bug prevents two HTTP calls in
    the same test from sharing app state cleanly.
    """
    from conftest import make_authed_client
    user_id = "acct-av-5"

    async def _seed(session):
        user = await session.get(User, user_id)
        if user is not None:
            user.avatar_url = _make_data_url()

    # Ensure the user row exists by creating a client (which seeds via conftest).
    client = make_authed_client(role="admin", user_id=user_id)
    run_db(_seed)
    assert _get_user(user_id).avatar_url is not None

    resp = client.delete("/api/v1/settings/account/avatar")
    assert resp.status_code == 200
    assert _get_user(user_id).avatar_url is None


# ── TOTP ──────────────────────────────────────────────────────────────────────

def test_post_totp_enroll_returns_qr_and_secret():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="acct-totp-1")

    resp = client.post("/api/v1/settings/account/totp")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["qrDataUrl"].startswith("data:image/png;base64,")
    assert len(body["secret"]) >= 16  # 20 raw bytes → 32 base32 chars

    # Server should NOT persist or enable TOTP yet.
    user = _get_user("acct-totp-1")
    assert user.totp_secret is None
    assert user.totp_enabled is False


def test_post_totp_verify_with_correct_code_enables_totp():
    """Stash pending secret directly, then verify in one HTTP call."""
    from conftest import make_authed_client
    from src.settings.account_endpoints import _generate_totp_secret, _stash_pending_totp
    from src.shared.totp import _totp_code_at  # type: ignore
    import time

    user_id = "acct-totp-2"
    secret = _generate_totp_secret()
    _stash_pending_totp(user_id, secret)

    code = _totp_code_at(secret, int(time.time()) // 30)
    resp = make_authed_client(role="admin", user_id=user_id).post(
        "/api/v1/settings/account/totp/verify", json={"code": code}
    )
    assert resp.status_code == 200, resp.text

    user = _get_user(user_id)
    assert user.totp_enabled is True
    assert user.totp_secret  # encrypted secret persisted
    assert user.totp_secret != secret  # stored encrypted, not raw
    assert user.totp_secret.startswith("gAAAAA")


def test_post_totp_verify_with_wrong_code_keeps_disabled():
    from conftest import make_authed_client
    from src.settings.account_endpoints import _generate_totp_secret, _stash_pending_totp

    user_id = "acct-totp-3"
    _stash_pending_totp(user_id, _generate_totp_secret())

    resp = make_authed_client(role="admin", user_id=user_id).post(
        "/api/v1/settings/account/totp/verify", json={"code": "000000"}
    )
    assert resp.status_code == 400

    user = _get_user(user_id)
    assert user.totp_enabled is False
    assert user.totp_secret is None


def test_post_totp_verify_rejects_non_numeric_code():
    from conftest import make_authed_client
    from src.settings.account_endpoints import _generate_totp_secret, _stash_pending_totp

    user_id = "acct-totp-4"
    _stash_pending_totp(user_id, _generate_totp_secret())

    resp = make_authed_client(role="admin", user_id=user_id).post(
        "/api/v1/settings/account/totp/verify", json={"code": "abcdef"}
    )
    assert resp.status_code == 400


def test_post_totp_verify_without_enrollment_returns_400():
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="acct-totp-5")

    resp = client.post("/api/v1/settings/account/totp/verify", json={"code": "123456"})
    assert resp.status_code == 400


def test_delete_totp_clears_secret_and_disables():
    """Seed user with TOTP enabled directly, then DELETE in one HTTP call."""
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

    resp = client.delete("/api/v1/settings/account/totp")
    assert resp.status_code == 200

    user = _get_user(user_id)
    assert user.totp_enabled is False
    assert user.totp_secret is None
