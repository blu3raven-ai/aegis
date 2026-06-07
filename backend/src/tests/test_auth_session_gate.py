"""Tests for SessionAuthMiddleware decision matrix.

Uses an in-memory _FakeService to avoid DB dependencies — the matrix is
pure logic; the DB-bound SessionService is exercised in test_auth_session.py.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.auth.cookies import SESSION_COOKIE_NAME
from src.auth.session_gate import SessionAuthMiddleware


class _FakeUser:
    def __init__(self, id: str, status: str = "active"):
        self.id = id
        self.status = status


class _FakeSession:
    def __init__(self, id: str, user: _FakeUser):
        self.id = id
        self.user_id = user.id
        self.user = user


class _FakeService:
    """In-memory stand-in for SessionService — keeps the gate tests fast and DB-free."""
    def __init__(self):
        self._store: dict[str, _FakeSession] = {}

    def add(self, session_id: str, user_id: str, status: str = "active"):
        self._store[session_id] = _FakeSession(session_id, _FakeUser(user_id, status))

    async def lookup(self, session_id: str):
        return self._store.get(session_id)


def _build(service):
    app = FastAPI()
    app.add_middleware(SessionAuthMiddleware, session_service_factory=lambda: service)

    @app.get("/")
    def home():
        return {"ok": True}

    @app.get("/api/v1/findings")
    def findings():
        return {"ok": True}

    @app.get("/login")
    def login():
        return {"ok": True}

    @app.get("/pending")
    def pending():
        return {"ok": True}

    @app.get("/_next/static/x.js")
    def static_file():
        return {"ok": True}

    @app.get("/graphql")
    def graphql_bare():
        return {"ok": True}

    @app.get("/graphql/api")
    def graphql():
        return {"ok": True}

    return app


def test_public_path_passes_without_cookie():
    client = TestClient(_build(_FakeService()))
    assert client.get("/login").status_code == 200


def test_static_prefix_passes_without_cookie():
    client = TestClient(_build(_FakeService()))
    assert client.get("/_next/static/x.js").status_code == 200


def test_no_cookie_on_api_returns_401():
    client = TestClient(_build(_FakeService()))
    assert client.get("/api/v1/findings").status_code == 401


def test_no_cookie_on_graphql_returns_401():
    client = TestClient(_build(_FakeService()))
    assert client.get("/graphql/api").status_code == 401


def test_no_cookie_on_page_returns_302_to_login():
    client = TestClient(_build(_FakeService()), follow_redirects=False)
    r = client.get("/")
    assert r.status_code == 302
    assert r.headers["location"] == "/login"


def test_unknown_session_on_api_returns_401():
    client = TestClient(_build(_FakeService()))
    client.cookies.set(SESSION_COOKIE_NAME, "ghost")
    assert client.get("/api/v1/findings").status_code == 401


def test_unknown_session_on_page_redirects_to_login():
    client = TestClient(_build(_FakeService()), follow_redirects=False)
    client.cookies.set(SESSION_COOKIE_NAME, "ghost")
    r = client.get("/")
    assert r.status_code == 302
    assert r.headers["location"] == "/login"


def test_valid_session_passes():
    svc = _FakeService()
    svc.add("sess1", "user1", status="active")
    client = TestClient(_build(svc))
    client.cookies.set(SESSION_COOKIE_NAME, "sess1")
    assert client.get("/").status_code == 200


def test_pending_user_redirects_to_pending():
    svc = _FakeService()
    svc.add("sess1", "user1", status="pending")
    client = TestClient(_build(svc), follow_redirects=False)
    client.cookies.set(SESSION_COOKIE_NAME, "sess1")
    r = client.get("/")
    assert r.status_code == 302
    assert r.headers["location"] == "/pending"


def test_active_user_on_pending_redirects_to_home():
    svc = _FakeService()
    svc.add("sess1", "user1", status="active")
    client = TestClient(_build(svc), follow_redirects=False)
    client.cookies.set(SESSION_COOKIE_NAME, "sess1")
    r = client.get("/pending")
    assert r.status_code == 302
    assert r.headers["location"] == "/"


def test_pending_user_can_access_pending():
    svc = _FakeService()
    svc.add("sess1", "user1", status="pending")
    client = TestClient(_build(svc))
    client.cookies.set(SESSION_COOKIE_NAME, "sess1")
    assert client.get("/pending").status_code == 200


# ── New regression / coverage tests ──────────────────────────────────────────


def test_graphqlinjector_path_does_not_match_api():
    """Defense-in-depth: /graphql prefix should not match arbitrary paths beginning with it."""
    app = FastAPI()
    app.add_middleware(SessionAuthMiddleware, session_service_factory=lambda: _FakeService())

    @app.get("/graphqlinjector")
    def injector():
        return {"ok": True}

    client = TestClient(app, follow_redirects=False)
    r = client.get("/graphqlinjector")
    # Not an API path → unauthenticated page request → 302 to /login, not 401
    assert r.status_code == 302
    assert r.headers["location"] == "/login"


def test_bare_graphql_classified_as_api():
    client = TestClient(_build(_FakeService()))
    assert client.get("/graphql").status_code == 401


def test_health_paths_are_public():
    app = FastAPI()
    app.add_middleware(SessionAuthMiddleware, session_service_factory=lambda: _FakeService())

    @app.get("/health/live")
    def live():
        return {"ok": True}

    @app.get("/health/ready")
    def ready():
        return {"ok": True}

    client = TestClient(app)
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 200


def test_openapi_and_docs_are_public():
    app = FastAPI()
    app.add_middleware(SessionAuthMiddleware, session_service_factory=lambda: _FakeService())
    client = TestClient(app)
    # FastAPI auto-mounts /openapi.json and /docs
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


def test_api2_prefix_does_not_match_api():
    """Trailing slash on /api/ prevents /api2/foo style mismatches."""
    app = FastAPI()
    app.add_middleware(SessionAuthMiddleware, session_service_factory=lambda: _FakeService())

    @app.get("/api2/v1/x")
    def api2():
        return {"ok": True}

    client = TestClient(app, follow_redirects=False)
    r = client.get("/api2/v1/x")
    # /api2/... is NOT API → unauthenticated page request → 302 to /login (not 401)
    assert r.status_code == 302
    assert r.headers["location"] == "/login"


def test_pending_user_on_api_returns_401():
    svc = _FakeService()
    svc.add("sess1", "user1", status="pending")
    client = TestClient(_build(svc))
    client.cookies.set(SESSION_COOKIE_NAME, "sess1")
    r = client.get("/api/v1/findings")
    assert r.status_code == 401
    assert r.json()["detail"] == "pending"


# ── Connection lifecycle ─────────────────────────────────────────────────────


class _TrackedDb:
    def __init__(self):
        self.close_count = 0

    async def close(self):
        self.close_count += 1


class _TrackedService:
    """Fake service that exposes a `db` attribute so we can assert the
    middleware releases the underlying connection after dispatch.
    """
    def __init__(self):
        self.db = _TrackedDb()
        self._store: dict[str, _FakeSession] = {}

    def add(self, session_id: str, user_id: str, status: str = "active"):
        self._store[session_id] = _FakeSession(session_id, _FakeUser(user_id, status))

    async def lookup(self, session_id: str):
        return self._store.get(session_id)


def _build_with_factory(factory):
    app = FastAPI()
    app.add_middleware(SessionAuthMiddleware, session_service_factory=factory)

    @app.get("/")
    def home():
        return {"ok": True}

    @app.get("/api/v1/findings")
    def findings():
        return {"ok": True}

    return app


def test_middleware_closes_db_after_successful_request():
    services: list[_TrackedService] = []

    def factory():
        svc = _TrackedService()
        svc.add("sess1", "user1", status="active")
        services.append(svc)
        return svc

    client = TestClient(_build_with_factory(factory))
    client.cookies.set(SESSION_COOKIE_NAME, "sess1")
    assert client.get("/").status_code == 200

    assert len(services) == 1
    assert services[0].db.close_count == 1


def test_middleware_closes_db_when_session_unknown():
    services: list[_TrackedService] = []

    def factory():
        svc = _TrackedService()
        services.append(svc)
        return svc

    client = TestClient(_build_with_factory(factory))
    client.cookies.set(SESSION_COOKIE_NAME, "ghost")
    assert client.get("/api/v1/findings").status_code == 401

    assert len(services) == 1
    assert services[0].db.close_count == 1


def test_middleware_closes_db_when_downstream_raises():
    services: list[_TrackedService] = []

    def factory():
        svc = _TrackedService()
        svc.add("sess1", "user1", status="active")
        services.append(svc)
        return svc

    app = FastAPI()
    app.add_middleware(SessionAuthMiddleware, session_service_factory=factory)

    @app.get("/boom")
    def boom():
        raise RuntimeError("downstream failure")

    client = TestClient(app, raise_server_exceptions=False)
    client.cookies.set(SESSION_COOKIE_NAME, "sess1")
    r = client.get("/boom")
    assert r.status_code == 500

    assert len(services) == 1
    assert services[0].db.close_count == 1
