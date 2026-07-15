"""End-to-end tests for /auth/login, /auth/login/verify, /auth/logout.

Uses a real Postgres DB. Each test gets a dedicated async engine (fresh
asyncpg connection pool) to avoid event-loop binding issues with TestClient,
which runs each request in its own anyio portal/loop.

Data seeding uses run_db (background thread) so the pytest-asyncio loop and
the TestClient loop never share connections.

AEGIS_AUDIT_LOG_ENABLED=false silences audit writes in tests.
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import struct
import time
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.auth.authentication.cookies import (
    CSRF_COOKIE_NAME,
    MFA_PENDING_COOKIE_NAME,
    SESSION_COOKIE_NAME,
)
from src.auth.authentication.login_router import _get_db, login_router
from src.db.engine import DATABASE_URL
from src.db.models import RateLimitBucket, User, UserSession



def _scrypt_hash(password: str) -> str:
    salt = bytes.fromhex("aabbccddeeff00112233445566778899")
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=64)
    return f"scrypt:v1:{salt.hex()}:{key.hex()}"


def _totp_code(secret_b32: str) -> str:
    """Compute the current TOTP code for a base32 secret."""
    key = base64.b32decode(secret_b32, casefold=True)
    counter = int(time.time()) // 30
    msg = struct.pack(">Q", counter)
    h = _hmac.new(key, msg, "sha1").digest()
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % 10**6).zfill(6)


def _seed(
    *,
    email: str,
    password_hash: str,
    totp_secret: str | None = None,
    totp_enabled: bool = False,
) -> str:
    """Insert a User synchronously via run_db. Returns the user id."""
    from src.db.helpers import run_db

    user_id = f"test-{uuid4()}"
    username = f"testlogin-{uuid4()}"

    async def _insert(session):
        session.add(User(
            id=user_id,
            username=username,
            email=email,
            password_hash=password_hash,
            status="active",
            totp_secret=totp_secret,
            totp_enabled=totp_enabled,
        ))

    run_db(_insert)
    return user_id


def _teardown(user_id: str) -> None:
    """Remove session and user rows created during a test."""
    from src.db.helpers import run_db

    async def _cleanup(session):
        await session.execute(delete(UserSession).where(UserSession.user_id == user_id))
        await session.execute(delete(User).where(User.id == user_id))

    run_db(_cleanup)


def _teardown_rl_ip(ip: str) -> None:
    from src.db.helpers import run_db

    async def _cleanup(session):
        await session.execute(delete(RateLimitBucket).where(
            RateLimitBucket.key.like(f"%:ip:{ip}%")
        ))

    run_db(_cleanup)


def _teardown_rl_user(email: str) -> None:
    from src.db.helpers import run_db

    async def _cleanup(session):
        await session.execute(delete(RateLimitBucket).where(
            RateLimitBucket.key.like(f"%:user:{email.lower()}%")
        ))

    run_db(_cleanup)


def _make_app(engine) -> FastAPI:
    """Build a minimal FastAPI app with login_router.

    The _get_db dependency is overridden to use the provided engine, which is
    freshly created per-test to avoid asyncpg event-loop binding conflicts.
    """
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _override_db():
        async with factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    app = FastAPI()
    app.include_router(login_router)
    app.dependency_overrides[_get_db] = _override_db
    return app



@pytest.fixture(autouse=True, scope="session")
def clean_testclient_rl_once():
    """Wipe any leftover testclient IP rate-limit rows before the suite starts.

    TestClient sends requests with host='testclient', so all login tests share
    the same IP bucket. A fresh bucket at suite start prevents cross-run bleed.
    Also wipe the ghost@example.com user bucket used by enumeration tests.
    """
    _teardown_rl_ip("testclient")
    _teardown_rl_user("ghost@example.com")
    yield


@pytest.fixture(autouse=True)
def _audit_disabled(monkeypatch):
    """Disable audit writes for the duration of each test.

    AuditRecorder uses run_db internally — that background loop is running,
    but we don't want test noise in the audit_events table and don't want to
    depend on it succeeding. Scoped per-test so the env var is restored after
    each test and doesn't bleed into audit_recorder tests.
    """
    monkeypatch.setenv("AEGIS_AUDIT_LOG_ENABLED", "false")
    monkeypatch.setenv("SESSION_SECRET", "test-secret-for-csrf-only")


@pytest.fixture
def app_client():
    """TestClient with a fresh engine per test.

    A fresh engine per test ensures asyncpg connections are not shared
    across different anyio event loops (TestClient creates a new loop
    for each portal invocation).

    Rate-limit buckets keyed on the TestClient's synthetic IP "testclient"
    are cleaned up at teardown so successive tests start with a clean slate.
    """
    engine = create_async_engine(DATABASE_URL, echo=False)
    app = _make_app(engine)
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client
    # Clean up IP-based rate limit buckets so subsequent tests aren't blocked.
    _teardown_rl_ip("testclient")


@pytest.fixture
def seed_user_with_password():
    """Seed a plain-password user; clean up after test."""
    password = "correct-horse-battery-staple"
    email = f"logintest+{uuid4()}@example.com"
    user_id = _seed(email=email, password_hash=_scrypt_hash(password))
    yield email, password, user_id
    _teardown(user_id)


@pytest.fixture
def seed_user_with_username_and_password():
    """Seed a user with both username and email; clean up after test."""
    from src.db.helpers import run_db

    password = "correct-horse-battery-staple"
    username = f"testlogin-{uuid4()}"
    email = f"logintest+{uuid4()}@example.com"
    user_id = f"test-{uuid4()}"

    async def _insert(session):
        session.add(User(
            id=user_id,
            username=username,
            email=email,
            password_hash=_scrypt_hash(password),
            status="active",
        ))

    run_db(_insert)
    yield username, email, password, user_id
    _teardown(user_id)


@pytest.fixture
def seed_mfa_user_with_password():
    """Seed a TOTP-enabled user; clean up after test."""
    password = "mfa-user-password-correct"
    totp_secret = "JBSWY3DPEHPK3PXP"  # standard TOTP test vector
    email = f"mfatest+{uuid4()}@example.com"
    user_id = _seed(
        email=email,
        password_hash=_scrypt_hash(password),
        totp_secret=totp_secret,
        totp_enabled=True,
    )
    totp_code = _totp_code(totp_secret)
    yield email, password, totp_code, user_id
    _teardown(user_id)



def test_login_with_valid_credentials_issues_session(app_client, seed_user_with_password):
    email, password, user_id = seed_user_with_password
    r = app_client.post("/api/v1/auth/login", json={"identifier": email, "password": password})
    assert r.status_code == 200
    assert SESSION_COOKIE_NAME in r.cookies
    assert CSRF_COOKIE_NAME in r.cookies
    body = r.json()
    assert body["user"]["id"] == user_id
    assert "session_id" not in body


def test_login_with_wrong_password_returns_401(app_client, seed_user_with_password):
    email, _, _ = seed_user_with_password
    r = app_client.post("/api/v1/auth/login", json={"identifier": email, "password": "wrong-password"})
    assert r.status_code == 401
    assert SESSION_COOKIE_NAME not in r.cookies
    assert r.json()["detail"] == "invalid credentials"


def test_login_with_unknown_email_returns_401_same_message(app_client):
    """No username enumeration — unknown identifier must return identical message and code."""
    r = app_client.post("/api/v1/auth/login", json={"identifier": "ghost@example.com", "password": "anything"})
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid credentials"


def test_login_rate_limit_kicks_in_after_5_attempts_same_ip(app_client):
    """6th attempt from the same IP within 60 s must return 429."""
    email = f"ratelimit-{uuid4()}@example.com"
    for _ in range(5):
        app_client.post("/api/v1/auth/login", json={"identifier": email, "password": "wrong"})
    r = app_client.post("/api/v1/auth/login", json={"identifier": email, "password": "wrong"})
    assert r.status_code == 429


def _replay_mfa_cookie(app_client, login_resp):
    """TestClient runs over http, so it won't resend the Secure ``__Host-`` MFA
    cookie automatically; replay it from the login response as a plain cookie."""
    app_client.cookies.set(
        MFA_PENDING_COOKIE_NAME, login_resp.cookies[MFA_PENDING_COOKIE_NAME]
    )


def test_login_with_mfa_sets_pending_cookie_not_body(
    app_client, seed_mfa_user_with_password
):
    email, password, _, _ = seed_mfa_user_with_password
    r = app_client.post("/api/v1/auth/login", json={"identifier": email, "password": password})
    assert r.status_code == 200
    assert SESSION_COOKIE_NAME not in r.cookies
    body = r.json()
    assert body["mfa_required"] is True
    # The token is delivered only as an HttpOnly cookie, never in the body.
    assert "pending_token" not in body
    assert MFA_PENDING_COOKIE_NAME in r.cookies


def test_login_by_username_succeeds(app_client, seed_user_with_username_and_password):
    """Username-based login (not email) — preserves BFF behavior."""
    username, _email, password, user_id = seed_user_with_username_and_password
    r = app_client.post("/api/v1/auth/login", json={"identifier": username, "password": password})
    assert r.status_code == 200
    assert SESSION_COOKIE_NAME in r.cookies
    assert CSRF_COOKIE_NAME in r.cookies
    body = r.json()
    assert body["user"]["id"] == user_id


def test_login_by_email_still_works_with_identifier_field(app_client, seed_user_with_username_and_password):
    """Email-based login via the identifier field still works."""
    _username, email, password, user_id = seed_user_with_username_and_password
    r = app_client.post("/api/v1/auth/login", json={"identifier": email, "password": password})
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["id"] == user_id



def test_login_verify_with_correct_totp_completes_login(
    app_client, seed_mfa_user_with_password
):
    email, password, totp_code, user_id = seed_mfa_user_with_password
    r1 = app_client.post("/api/v1/auth/login", json={"identifier": email, "password": password})
    _replay_mfa_cookie(app_client, r1)

    r2 = app_client.post("/api/v1/auth/login/verify", json={"code": totp_code})
    assert r2.status_code == 200
    assert SESSION_COOKIE_NAME in r2.cookies
    assert CSRF_COOKIE_NAME in r2.cookies
    assert r2.json()["user"]["id"] == user_id


def test_login_verify_with_bad_code_returns_401(app_client, seed_mfa_user_with_password):
    email, password, _, _ = seed_mfa_user_with_password
    r1 = app_client.post("/api/v1/auth/login", json={"identifier": email, "password": password})
    _replay_mfa_cookie(app_client, r1)

    r2 = app_client.post("/api/v1/auth/login/verify", json={"code": "000000"})
    assert r2.status_code == 401
    assert SESSION_COOKIE_NAME not in r2.cookies


def test_login_verify_with_expired_or_unknown_token_returns_401(app_client):
    app_client.cookies.set(MFA_PENDING_COOKIE_NAME, "nonexistent-ghost-token")
    r = app_client.post("/api/v1/auth/login/verify", json={"code": "123456"})
    assert r.status_code == 401


def test_login_verify_token_is_single_use(app_client, seed_mfa_user_with_password):
    """A pending token consumed by a successful verify cannot be replayed."""
    email, password, totp_code, _ = seed_mfa_user_with_password
    r1 = app_client.post("/api/v1/auth/login", json={"identifier": email, "password": password})
    _replay_mfa_cookie(app_client, r1)

    r2 = app_client.post("/api/v1/auth/login/verify", json={"code": totp_code})
    assert r2.status_code == 200

    # The successful verify cleared the cookie; re-supply it to prove the *token*
    # (not just the cookie) is single-use.
    _replay_mfa_cookie(app_client, r1)
    replay = app_client.post("/api/v1/auth/login/verify", json={"code": totp_code})
    assert replay.status_code == 401


def test_login_verify_burns_token_after_max_wrong_codes(
    app_client, seed_mfa_user_with_password, monkeypatch
):
    """After MAX_MFA_ATTEMPTS wrong codes the pending token is invalidated, so
    even the correct code afterwards fails — forcing a fresh password login.

    Rate-limit primitives are stubbed to isolate the per-token attempt counter
    (the shared TestClient IP bucket would otherwise 429 before the counter is
    exhausted).
    """
    import src.auth.authentication.login_router as lr

    async def _noop_ip(request, db):
        return None

    async def _noop_user(email, db):
        return None

    monkeypatch.setattr(lr, "_rate_limit_ip", _noop_ip)
    monkeypatch.setattr(lr, "_rate_limit_user", _noop_user)

    email, password, totp_code, _ = seed_mfa_user_with_password
    r1 = app_client.post("/api/v1/auth/login", json={"identifier": email, "password": password})

    for _ in range(lr.MAX_MFA_ATTEMPTS):
        _replay_mfa_cookie(app_client, r1)
        bad = app_client.post("/api/v1/auth/login/verify", json={"code": "000000"})
        assert bad.status_code == 401

    # Token is now gone: the correct code no longer completes login.
    _replay_mfa_cookie(app_client, r1)
    good = app_client.post("/api/v1/auth/login/verify", json={"code": totp_code})
    assert good.status_code == 401
    assert SESSION_COOKIE_NAME not in good.cookies


def test_login_verify_invokes_ip_rate_limit(app_client, monkeypatch):
    """/login/verify must run the IP rate-limit primitive before the token check,
    so a cookie-less brute force of the endpoint is still throttled."""
    import src.auth.authentication.login_router as lr

    called = {"ip": False}

    async def _spy_ip(request, db):
        called["ip"] = True

    monkeypatch.setattr(lr, "_rate_limit_ip", _spy_ip)

    r = app_client.post("/api/v1/auth/login/verify", json={"code": "123456"})
    assert r.status_code == 401
    assert called["ip"] is True
    assert called["ip"] is True



def test_logout_revokes_session_and_clears_cookies(app_client, seed_user_with_password):
    email, password, _ = seed_user_with_password
    login = app_client.post("/api/v1/auth/login", json={"identifier": email, "password": password})
    assert login.status_code == 200

    session_cookie = login.cookies[SESSION_COOKIE_NAME]
    app_client.cookies.set(SESSION_COOKIE_NAME, session_cookie)

    logout = app_client.post("/api/v1/auth/logout")
    assert logout.status_code == 200

    sc_headers = logout.headers.get_list("set-cookie")
    assert any(SESSION_COOKIE_NAME in h and "Max-Age=0" in h for h in sc_headers), (
        f"Expected a clearing Set-Cookie for {SESSION_COOKIE_NAME}; got: {sc_headers}"
    )


def test_logout_is_idempotent_without_session(app_client):
    """Logout with no session cookie must return 200 (idempotent)."""
    r = app_client.post("/api/v1/auth/logout")
    assert r.status_code == 200
    assert r.json() == {"ok": True}



def test_login_timing_is_consistent_unknown_vs_wrong_password(app_client, seed_user_with_password):
    """No user-enumeration via response timing.

    Best-effort test — not a definitive timing oracle proof, but catches a regression
    where one branch skips scrypt entirely.
    """
    import time

    from src.db.helpers import run_db

    email, _, _ = seed_user_with_password

    def _clear_login_ip_buckets() -> None:
        # Reset the per-IP login limiter (5/60s) so repeated samples below don't
        # trip it — a 429 would short-circuit the handler and ruin the timing.
        async def _c(session):
            await session.execute(
                delete(RateLimitBucket).where(
                    RateLimitBucket.key.like("/api/v1/auth/login:ip:%")
                )
            )
        run_db(_c)

    def _timed(identifier: str, password: str) -> float:
        _clear_login_ip_buckets()
        t0 = time.perf_counter()
        resp = app_client.post(
            "/api/v1/auth/login", json={"identifier": identifier, "password": password}
        )
        elapsed = time.perf_counter() - t0
        assert resp.status_code != 429, "timing sample hit the rate limiter"
        return elapsed

    # Warm the scrypt path before measuring — the first call after process start
    # absorbs interpreter/import overhead unrelated to the property under test.
    _timed(email, "warmup")

    # Take several interleaved samples and compare the MINIMUMS. The fastest
    # observed run reflects scrypt's true cost; GC/scheduler jitter only ever
    # inflates a sample, so a single slow shot (which made the old single-sample
    # ratio flake on a busy CI box) is discarded by min().
    samples = 5
    wrong_pw = [_timed(email, "wrong") for _ in range(samples)]
    unknown_user = [_timed(f"ghost-timing-{uuid4()}@example.com", "wrong") for _ in range(samples)]

    fastest_wrong = min(wrong_pw)
    fastest_unknown = min(unknown_user)

    # Each branch must actually run scrypt (~60ms); a skipped branch returns in
    # well under 20ms, so a sub-20ms minimum means scrypt was bypassed.
    assert fastest_unknown > 0.020, (
        f"unknown-user min {fastest_unknown * 1000:.1f}ms; scrypt was likely skipped"
    )
    assert fastest_wrong > 0.020, (
        f"wrong-password min {fastest_wrong * 1000:.1f}ms; scrypt was likely skipped"
    )
    # Comparing minima removes jitter, so a >3x gap is a genuine timing-oracle signal.
    ratio = max(fastest_wrong, fastest_unknown) / min(fastest_wrong, fastest_unknown)
    assert ratio < 3.0, (
        f"timing ratio {ratio:.2f} suggests enumeration leak; "
        f"wrong_pw_min={fastest_wrong * 1000:.1f}ms, unknown_min={fastest_unknown * 1000:.1f}ms"
    )


def test_login_router_fails_loudly_without_session_secret(monkeypatch):
    """SESSION_SECRET being unset must raise, not silently HMAC with empty key."""
    from src.shared.config import get_session_secret

    monkeypatch.delenv("SESSION_SECRET", raising=False)
    import pytest
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        get_session_secret()


def test_login_router_fails_loudly_with_empty_session_secret(monkeypatch):
    """SESSION_SECRET set to empty string must also raise."""
    from src.shared.config import get_session_secret

    monkeypatch.setenv("SESSION_SECRET", "")
    import pytest
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        get_session_secret()
