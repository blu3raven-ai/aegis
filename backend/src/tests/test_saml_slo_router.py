"""End-to-end tests for SAML Single Logout (SLO).

Exercises both IdP-initiated SLO (`POST /auth/sso/saml/slo`) and SP-initiated
SLO (`GET /auth/sso/saml/slo/initiate` + the IdP `LogoutResponse` callback),
plus the `/auth/logout` handoff wiring.

pysaml2's signature crypto is mocked at the helper boundary because xmlsec1
is not installed in this test environment — the e2e suite covers signed
round-trips against a real test IdP. These tests cover routing, session
lookup, status-code branching (Success vs Requester), binding selection
(HTTP-Redirect vs HTTP-POST), relay-state binding to a session, and the
logout-handler handoff for SAML vs local-auth sessions.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

os.environ.setdefault("APP_SECRET", Fernet.generate_key().decode())
os.environ.setdefault("SESSION_SECRET", "test-only-session-secret-not-for-production")

from src.auth.authentication.cookies import SESSION_COOKIE_NAME  # noqa: E402
from src.auth.authentication.login_router import _get_db, login_router  # noqa: E402
from src.auth.federation import saml as saml_helpers  # noqa: E402
from src.auth.federation import saml_router as saml_router_mod  # noqa: E402
from src.auth.federation.saml_router import saml_router  # noqa: E402
from src.auth.federation.state import encode_saml_slo_state  # noqa: E402
from src.db.engine import DATABASE_URL  # noqa: E402
from src.db.models import SsoConfig, User, UserSession  # noqa: E402
from src.security.crypto import encrypt  # noqa: E402

# pysaml2 binding URIs are referenced as bare strings in the test fixtures so
# the import doesn't transitively trigger xmlsec1 resolution.
_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"


@pytest.fixture(autouse=True)
def _audit_disabled(monkeypatch):
    monkeypatch.setenv("AEGIS_AUDIT_LOG_ENABLED", "false")


def _make_app(engine) -> FastAPI:
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _override_db():
        async with factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    app = FastAPI()
    app.include_router(saml_router)
    app.include_router(login_router)
    app.dependency_overrides[_get_db] = _override_db
    return app


@pytest.fixture
def app_client():
    engine = create_async_engine(DATABASE_URL, echo=False)
    app = _make_app(engine)
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client


def _seed_sso_config(*, enabled: bool = True, protocol: str | None = "saml") -> None:
    """Seed the singleton SsoConfig row.

    The real pysaml2 key blobs are not used by these tests (helpers are
    mocked) but a non-null `saml_metadata_xml` and `saml_sp_private_key_enc`
    are needed for `_load_config` to return the row rather than None.
    """
    from src.db.helpers import run_db

    async def _do(session):
        row = SsoConfig(
            id=1,
            enabled=enabled,
            protocol=protocol,
            saml_metadata_xml="<EntityDescriptor xmlns=\"x\">noop</EntityDescriptor>",
            saml_sp_private_key_enc=encrypt("-----BEGIN PRIVATE KEY-----\nnoop\n-----END PRIVATE KEY-----\n"),
            saml_sp_certificate="-----BEGIN CERTIFICATE-----\nnoop\n-----END CERTIFICATE-----\n",
        )
        session.add(row)

    run_db(_do)


def _wipe_sso_config() -> None:
    from src.db.helpers import run_db

    async def _do(session):
        await session.execute(delete(SsoConfig).where(SsoConfig.id == 1))

    run_db(_do)


def _seed_saml_user(*, name_id: str, email: str | None = None) -> tuple[str, str]:
    """Insert a SAML-linked User + active UserSession. Returns (user_id, session_id)."""
    from datetime import timedelta

    from src.db.helpers import run_db
    from src.db.models import utcnow

    user_id = f"saml-{uuid4()}"
    session_id = f"sess-{uuid4().hex}"
    user_email = email or f"saml+{uuid4()}@example.com"

    async def _do(session):
        session.add(User(
            id=user_id,
            username=user_email,
            email=user_email,
            password_hash="",
            status="active",
            sso_subject=name_id,
            sso_protocol="saml",
        ))
        await session.flush()
        now = utcnow()
        session.add(UserSession(
            id=session_id,
            user_id=user_id,
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(hours=8),
        ))

    run_db(_do)
    return user_id, session_id


def _seed_local_user() -> tuple[str, str]:
    """Insert a non-SAML local User + active UserSession."""
    from datetime import timedelta

    from src.db.helpers import run_db
    from src.db.models import utcnow

    user_id = f"local-{uuid4()}"
    session_id = f"sess-{uuid4().hex}"
    user_email = f"local+{uuid4()}@example.com"

    async def _do(session):
        session.add(User(
            id=user_id,
            username=user_email,
            email=user_email,
            password_hash="",
            status="active",
        ))
        await session.flush()
        now = utcnow()
        session.add(UserSession(
            id=session_id,
            user_id=user_id,
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(hours=8),
        ))

    run_db(_do)
    return user_id, session_id


def _session_is_revoked(session_id: str) -> bool:
    from sqlalchemy import select

    from src.db.helpers import run_db

    async def _do(session) -> bool:
        row = (
            await session.execute(
                select(UserSession).where(UserSession.id == session_id)
            )
        ).scalar_one_or_none()
        return row is not None and row.revoked_at is not None

    return run_db(_do)


def _teardown_user(user_id: str) -> None:
    from src.db.helpers import run_db

    async def _do(session):
        await session.execute(delete(UserSession).where(UserSession.user_id == user_id))
        await session.execute(delete(User).where(User.id == user_id))

    run_db(_do)


@pytest.fixture(autouse=True)
def _wipe_sso_around_test():
    _wipe_sso_config()
    yield
    _wipe_sso_config()


# -------------------------------------------------------------------------
# IdP-initiated SLO
# -------------------------------------------------------------------------


def test_idp_initiated_slo_redirect_binding_revokes_session(
    app_client, monkeypatch,
):
    """Mock IdP sends a LogoutRequest via HTTP-Redirect for an active SAML
    session. The endpoint must revoke the session, build a Success
    LogoutResponse, and respond per the inbound binding (redirect → 302)."""
    name_id = f"name-id-{uuid4()}"
    _seed_sso_config()
    user_id, sess_id = _seed_saml_user(name_id=name_id)

    captured: dict = {}

    def _fake_parse(cfg, origin, saml_request, binding, **kwargs):
        captured["parse_binding"] = binding
        captured["saml_request"] = saml_request
        return saml_helpers.SamlSloRequest(
            request_id="idp-req-id-123",
            name_id=name_id,
            raw=object(),
        )

    def _fake_build_response(cfg, origin, request_msg, request_binding, *, success, relay_state=None):
        captured["response_success"] = success
        captured["response_binding"] = request_binding
        return saml_helpers.SamlSloDispatch(
            method="GET", url="https://idp.example.com/slo?SAMLResponse=ok", body="",
        )

    monkeypatch.setattr(saml_router_mod, "parse_idp_logout_request", _fake_parse)
    monkeypatch.setattr(saml_router_mod, "build_idp_logout_response", _fake_build_response)

    try:
        r = app_client.get(
            "/auth/sso/saml/slo",
            params={"SAMLRequest": "encoded-saml-request"},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert r.headers["location"] == "https://idp.example.com/slo?SAMLResponse=ok"
        assert captured["parse_binding"] == _REDIRECT
        assert captured["response_success"] is True
        assert captured["response_binding"] == _REDIRECT
        assert _session_is_revoked(sess_id)
    finally:
        _teardown_user(user_id)


def test_idp_initiated_slo_post_binding_returns_form(app_client, monkeypatch):
    """The same flow over HTTP-POST: a different pysaml2 code path renders
    an HTML auto-submit form rather than a redirect. Both must work."""
    name_id = f"name-id-{uuid4()}"
    _seed_sso_config()
    user_id, sess_id = _seed_saml_user(name_id=name_id)

    captured: dict = {}

    def _fake_parse(cfg, origin, saml_request, binding, **kwargs):
        captured["parse_binding"] = binding
        return saml_helpers.SamlSloRequest(
            request_id="idp-req-id-post-1",
            name_id=name_id,
            raw=object(),
        )

    def _fake_build_response(cfg, origin, request_msg, request_binding, *, success, relay_state=None):
        captured["response_binding"] = request_binding
        return saml_helpers.SamlSloDispatch(
            method="POST",
            url="https://idp.example.com/slo",
            body="<html><body><form action=\"...\"></form></body></html>",
        )

    monkeypatch.setattr(saml_router_mod, "parse_idp_logout_request", _fake_parse)
    monkeypatch.setattr(saml_router_mod, "build_idp_logout_response", _fake_build_response)

    try:
        r = app_client.post(
            "/auth/sso/saml/slo",
            data={"SAMLRequest": "encoded-saml-request", "RelayState": "rs-1"},
            follow_redirects=False,
        )
        assert r.status_code == 200
        assert "<form" in r.text  # rendered auto-submit form body forwarded verbatim
        assert captured["parse_binding"] == _POST
        assert captured["response_binding"] == _POST
        assert _session_is_revoked(sess_id)
    finally:
        _teardown_user(user_id)


def test_idp_initiated_slo_unknown_nameid_returns_requester_status(
    app_client, monkeypatch,
):
    """A LogoutRequest whose NameID doesn't match any active session must
    return a LogoutResponse with status `Requester`, not a 500."""
    _seed_sso_config()
    captured: dict = {}

    def _fake_parse(cfg, origin, saml_request, binding, **kwargs):
        return saml_helpers.SamlSloRequest(
            request_id="idp-req-id-unknown",
            name_id="no-such-user",
            raw=object(),
        )

    def _fake_build_response(cfg, origin, request_msg, request_binding, *, success, relay_state=None):
        captured["response_success"] = success
        return saml_helpers.SamlSloDispatch(
            method="GET", url="https://idp.example.com/slo?SAMLResponse=err", body="",
        )

    monkeypatch.setattr(saml_router_mod, "parse_idp_logout_request", _fake_parse)
    monkeypatch.setattr(saml_router_mod, "build_idp_logout_response", _fake_build_response)

    r = app_client.get(
        "/auth/sso/saml/slo",
        params={"SAMLRequest": "encoded-saml-request"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert captured["response_success"] is False


def test_idp_initiated_slo_invalid_request_returns_400(app_client, monkeypatch):
    """A LogoutRequest the SP can't verify must return 400 — never trust the
    NameID from an unverified payload."""
    _seed_sso_config()

    def _fake_parse(*args, **kwargs):
        raise RuntimeError("signature invalid")

    monkeypatch.setattr(saml_router_mod, "parse_idp_logout_request", _fake_parse)

    r = app_client.get(
        "/auth/sso/saml/slo",
        params={"SAMLRequest": "bogus"},
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_idp_initiated_slo_missing_payload_returns_400(app_client):
    _seed_sso_config()
    r = app_client.get("/auth/sso/saml/slo", follow_redirects=False)
    assert r.status_code == 400


# -------------------------------------------------------------------------
# Unconfigured SAML
# -------------------------------------------------------------------------


def test_slo_endpoint_returns_404_when_saml_not_configured(app_client):
    """Mirrors the existing /metadata pattern in saml_router.py."""
    r = app_client.get(
        "/auth/sso/saml/slo",
        params={"SAMLRequest": "x"},
        follow_redirects=False,
    )
    assert r.status_code == 404

    r2 = app_client.post(
        "/auth/sso/saml/slo",
        data={"SAMLRequest": "x"},
        follow_redirects=False,
    )
    assert r2.status_code == 404


def test_slo_initiate_falls_through_to_login_when_saml_not_configured(app_client):
    """Idempotent — `/slo/initiate` should still produce a clean cookie-clear
    + /login redirect so callers can use it as a logout link unconditionally."""
    r = app_client.get("/auth/sso/saml/slo/initiate", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/login"
    set_cookies = r.headers.get_list("set-cookie")
    assert any(SESSION_COOKIE_NAME in c and "Max-Age=0" in c for c in set_cookies)


def test_inline_logout_still_clears_cookie_when_saml_not_configured(app_client):
    """The /auth/logout handoff must only fire when SAML is fully set up. When
    SsoConfig is absent the existing inline cookie-clear path runs as today."""
    _user_id, sess_id = _seed_local_user()
    try:
        app_client.cookies.set(SESSION_COOKIE_NAME, sess_id)
        r = app_client.post("/api/v1/auth/logout", follow_redirects=False)
        assert r.status_code == 200
        set_cookies = r.headers.get_list("set-cookie")
        assert any(SESSION_COOKIE_NAME in c and "Max-Age=0" in c for c in set_cookies)
        assert _session_is_revoked(sess_id)
    finally:
        _teardown_user(_user_id)


# -------------------------------------------------------------------------
# Logout handoff wiring
# -------------------------------------------------------------------------


def test_logout_for_non_saml_session_still_clears_inline_even_when_saml_configured(
    app_client, monkeypatch,
):
    """A local-auth user's /auth/logout must NOT hand off to SP-initiated SLO
    even when SAML SLO is configured — only SAML-authenticated sessions do."""
    _seed_sso_config()
    monkeypatch.setattr(saml_helpers, "idp_supports_slo", lambda *args, **kwargs: True)

    user_id, sess_id = _seed_local_user()
    try:
        app_client.cookies.set(SESSION_COOKIE_NAME, sess_id)
        r = app_client.post("/api/v1/auth/logout", follow_redirects=False)
        assert r.status_code == 200
        set_cookies = r.headers.get_list("set-cookie")
        assert any(SESSION_COOKIE_NAME in c and "Max-Age=0" in c for c in set_cookies)
        assert _session_is_revoked(sess_id)
    finally:
        _teardown_user(user_id)


def test_logout_for_saml_session_redirects_to_slo_initiate(app_client, monkeypatch):
    """A SAML-authenticated /auth/logout must redirect to /slo/initiate when
    the IdP advertises SLO. This is the shared-workstation fix."""
    _seed_sso_config()
    monkeypatch.setattr(
        "src.auth.federation.saml.idp_supports_slo",
        lambda *args, **kwargs: True,
    )

    user_id, sess_id = _seed_saml_user(name_id=f"name-{uuid4()}")
    try:
        app_client.cookies.set(SESSION_COOKIE_NAME, sess_id)
        r = app_client.post("/api/v1/auth/logout", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/auth/sso/saml/slo/initiate"
        # Session must NOT be revoked yet — SLO flow handles that.
        assert not _session_is_revoked(sess_id)
    finally:
        _teardown_user(user_id)


def test_logout_for_saml_session_falls_through_when_idp_lacks_slo(
    app_client, monkeypatch,
):
    """If the IdP metadata doesn't advertise a SingleLogoutService the
    handoff must be skipped — clearing inline is better than redirecting
    into a flow the IdP can't complete."""
    _seed_sso_config()
    monkeypatch.setattr(
        "src.auth.federation.saml.idp_supports_slo",
        lambda *args, **kwargs: False,
    )

    user_id, sess_id = _seed_saml_user(name_id=f"name-{uuid4()}")
    try:
        app_client.cookies.set(SESSION_COOKIE_NAME, sess_id)
        r = app_client.post("/api/v1/auth/logout", follow_redirects=False)
        assert r.status_code == 200
        set_cookies = r.headers.get_list("set-cookie")
        assert any(SESSION_COOKIE_NAME in c and "Max-Age=0" in c for c in set_cookies)
        assert _session_is_revoked(sess_id)
    finally:
        _teardown_user(user_id)


# -------------------------------------------------------------------------
# SP-initiated SLO
# -------------------------------------------------------------------------


def test_sp_initiated_slo_redirects_to_idp_with_signed_relay_state(
    app_client, monkeypatch,
):
    """An active SAML session hitting `/slo/initiate` must produce a redirect
    to the IdP's SLO URL, with relay state that the SP can verify on the
    return leg to clear the right session."""
    name_id = f"name-id-{uuid4()}"
    _seed_sso_config()
    user_id, sess_id = _seed_saml_user(name_id=name_id)

    captured: dict = {}

    def _fake_build(cfg, origin, name_id_text, *, request_id, relay_state):
        captured["request_id"] = request_id
        captured["relay_state"] = relay_state
        captured["name_id"] = name_id_text
        return saml_helpers.SamlSloDispatch(
            method="GET",
            url=f"https://idp.example.com/slo?SAMLRequest=enc&RelayState={relay_state}",
            body="",
        )

    monkeypatch.setattr(saml_router_mod, "build_sp_logout_request", _fake_build)

    try:
        app_client.cookies.set(SESSION_COOKIE_NAME, sess_id)
        r = app_client.get("/auth/sso/saml/slo/initiate", follow_redirects=False)
        assert r.status_code == 302
        location = r.headers["location"]
        assert location.startswith("https://idp.example.com/slo?")
        assert captured["name_id"] == name_id
        # request_id is pre-generated so it can be bound into the relay
        # state AND the LogoutRequest message ID. The IdP echoes it back as
        # `InResponseTo` so the callback can match this exact session.
        assert captured["request_id"].startswith("_aegis-slo-")
        from src.auth.federation.state import decode_saml_slo_state
        decoded = decode_saml_slo_state(captured["relay_state"])
        assert decoded["request_id"] == captured["request_id"]
        assert decoded["session_id"] == sess_id
    finally:
        _teardown_user(user_id)


def test_sp_initiated_slo_callback_clears_cookie_and_revokes_session(
    app_client, monkeypatch,
):
    """The IdP's LogoutResponse callback (via the same /slo endpoint) must
    verify the response, revoke the bound session, clear the cookie, and
    redirect to /login."""
    _seed_sso_config()
    user_id, sess_id = _seed_saml_user(name_id=f"name-{uuid4()}")
    relay_state = encode_saml_slo_state(
        request_id="sp-req-id-callback-1", session_id=sess_id,
    )

    def _fake_verify(cfg, origin, saml_response, binding):
        return "sp-req-id-callback-1"

    monkeypatch.setattr(saml_router_mod, "verify_idp_logout_response", _fake_verify)

    try:
        r = app_client.get(
            "/auth/sso/saml/slo",
            params={"SAMLResponse": "x", "RelayState": relay_state},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert r.headers["location"] == "/login"
        set_cookies = r.headers.get_list("set-cookie")
        assert any(SESSION_COOKIE_NAME in c and "Max-Age=0" in c for c in set_cookies)
        assert _session_is_revoked(sess_id)
    finally:
        _teardown_user(user_id)


def test_sp_initiated_slo_callback_with_mismatched_request_id_clears_safely(
    app_client, monkeypatch,
):
    """If the IdP's `InResponseTo` doesn't match the relay state's request_id,
    we still clear the cookie + redirect to /login (the user wanted to log
    out either way) but do NOT use the mismatched relay state to revoke a
    session that may not be ours."""
    _seed_sso_config()
    user_id, sess_id = _seed_saml_user(name_id=f"name-{uuid4()}")
    relay_state = encode_saml_slo_state(
        request_id="expected-req-id", session_id=sess_id,
    )

    def _fake_verify(*args, **kwargs):
        return "different-req-id"

    monkeypatch.setattr(saml_router_mod, "verify_idp_logout_response", _fake_verify)

    try:
        r = app_client.get(
            "/auth/sso/saml/slo",
            params={"SAMLResponse": "x", "RelayState": relay_state},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert r.headers["location"] == "/login"
        # Session NOT revoked since the request_id didn't match — but the
        # cookie WAS cleared (caller's intent was logout).
        assert not _session_is_revoked(sess_id)
    finally:
        _teardown_user(user_id)


def test_sp_initiated_slo_initiate_for_non_saml_session_falls_through(
    app_client, monkeypatch,
):
    """A user with a local session (not SAML-authenticated) hitting
    /slo/initiate must fall through to the inline cookie-clear path."""
    _seed_sso_config()
    user_id, sess_id = _seed_local_user()

    def _fake_build(*args, **kwargs):  # pragma: no cover — must not be called
        raise AssertionError(
            "build_sp_logout_request should not be called for non-SAML session"
        )

    monkeypatch.setattr(saml_router_mod, "build_sp_logout_request", _fake_build)

    try:
        app_client.cookies.set(SESSION_COOKIE_NAME, sess_id)
        r = app_client.get("/auth/sso/saml/slo/initiate", follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/login"
        set_cookies = r.headers.get_list("set-cookie")
        assert any(SESSION_COOKIE_NAME in c and "Max-Age=0" in c for c in set_cookies)
    finally:
        _teardown_user(user_id)
