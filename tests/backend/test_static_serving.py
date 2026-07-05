"""Tests for the static UI mount + SPA fallback."""
import pathlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _restore_main_module():
    """Restore src.main.app to the pre-test instance after each test.

    Tests in this module call reload(src.main) with a temporary STATIC_ROOT,
    which replaces src.main.app with a brand-new FastAPI instance that has
    static mounts + spa_fallback registered.  Without cleanup that new app
    object is visible to later tests that do ``from src.main import app``,
    causing CSRF mismatches and missing middleware.

    Strategy: save the original app object before the test, then point
    src.main.app back to it in teardown so other modules see the original app.
    """
    import src.main
    original_app = src.main.app
    yield
    src.main.app = original_app


def _client(monkeypatch, static_root: pathlib.Path):
    monkeypatch.setenv("STATIC_ROOT", str(static_root))
    from importlib import reload
    import src.main
    reload(src.main)
    return TestClient(src.main.app)


class _FakeUser:
    status = "active"
    role_id = "role_admin"


class _FakeSession:
    user_id = "test-user"
    user = _FakeUser()


def _authed_client(monkeypatch, static_root: pathlib.Path):
    """Reload the app against ``static_root`` and return an authenticated client.

    The session gate redirects unauthenticated requests for in-app routes to
    /login, so exercising the SPA fallback for those routes requires a session —
    which mirrors how a signed-in user actually reaches them. The session lookup
    is stubbed to an in-memory active session so the test never touches the
    database (and so avoids cross-event-loop asyncpg conflicts from the reload).
    """
    monkeypatch.setenv("STATIC_ROOT", str(static_root))
    from importlib import reload
    import src.main
    reload(src.main)

    from src.auth.authentication import session as session_mod
    from src.auth.authentication.cookies import SESSION_COOKIE_NAME

    async def _fake_lookup(self, session_id):
        return _FakeSession()

    monkeypatch.setattr(session_mod.SessionService, "lookup", _fake_lookup)

    client = TestClient(src.main.app)
    client.cookies.set(SESSION_COOKIE_NAME, "fake-session")
    return client


def test_static_index_html_served_at_root(tmp_path, monkeypatch):
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("<!doctype html><title>aegis</title>")
    client = _authed_client(monkeypatch, static_root)
    r = client.get("/")
    assert r.status_code == 200
    assert "<title>aegis</title>" in r.text


def test_static_asset_served(tmp_path, monkeypatch):
    static_root = tmp_path / "static"
    static_root.mkdir(parents=True)
    (static_root / "_next" / "static").mkdir(parents=True)
    (static_root / "_next" / "static" / "main.js").write_text("console.log('hi');")
    (static_root / "index.html").write_text("ok")
    client = _client(monkeypatch, static_root)
    r = client.get("/_next/static/main.js")
    assert r.status_code == 200
    assert "console.log" in r.text


def test_unknown_route_serves_404_document_with_404_status(tmp_path, monkeypatch):
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("<!doctype html><title>spa</title>")
    (static_root / "404.html").write_text("<!doctype html><title>not found</title>")
    client = _authed_client(monkeypatch, static_root)
    r = client.get("/does/not/exist")
    assert r.status_code == 404
    assert "<title>not found</title>" in r.text
    # Must never silently fall back to the home shell.
    assert "<title>spa</title>" not in r.text


def test_unknown_route_returns_404_when_no_404_document(tmp_path, monkeypatch):
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("<!doctype html><title>spa</title>")
    client = _authed_client(monkeypatch, static_root)
    r = client.get("/does/not/exist")
    assert r.status_code == 404
    assert "<title>spa</title>" not in r.text


def test_prerendered_route_still_served(tmp_path, monkeypatch):
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("<!doctype html><title>spa</title>")
    (static_root / "findings.html").write_text("<!doctype html><title>findings</title>")
    client = _authed_client(monkeypatch, static_root)
    r = client.get("/findings")
    assert r.status_code == 200
    assert "<title>findings</title>" in r.text


def test_unauthenticated_app_route_redirects_to_login(tmp_path, monkeypatch):
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("<!doctype html><title>spa</title>")
    (static_root / "404.html").write_text("<!doctype html><title>not found</title>")
    client = _client(monkeypatch, static_root)
    r = client.get("/does/not/exist", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/login"


def test_api_routes_are_not_swallowed_by_static(tmp_path, monkeypatch):
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("spa")
    client = _client(monkeypatch, static_root)
    r = client.get("/api/v1/findings")
    assert r.status_code == 401


def test_health_route_returns_json_not_html(tmp_path, monkeypatch):
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("spa")
    client = _client(monkeypatch, static_root)
    r = client.get("/health/live")
    assert r.status_code == 200
    assert "application/json" in r.headers.get("Content-Type", "")


def test_csp_contains_sha256_hashes_when_static_export_present(tmp_path, monkeypatch):
    """When the static export is present, CSP script-src includes sha256- entries
    derived from the actual JS chunks and never includes 'unsafe-inline'."""
    static_root = tmp_path / "static"
    chunks = static_root / "_next" / "static" / "chunks"
    chunks.mkdir(parents=True)
    (chunks / "webpack-abc.js").write_text("var x=1;")
    (chunks / "main-def.js").write_text("var y=2;")
    (static_root / "index.html").write_text("spa")

    monkeypatch.setenv("STATIC_ROOT", str(static_root))
    from importlib import reload
    import src.main
    reload(src.main)
    client = TestClient(src.main.app)
    r = client.get("/health/live")
    csp = r.headers.get("Content-Security-Policy", "")
    # script-src must contain at least one sha256- entry and 'strict-dynamic'
    script_src_section = next(p for p in csp.split(";") if "script-src" in p)
    assert "'sha256-" in script_src_section
    assert "'strict-dynamic'" in script_src_section
    assert "'unsafe-inline'" not in script_src_section


def test_unmatched_route_csp_defaults_to_404_page(tmp_path, monkeypatch):
    """The CSP fallback for unmatched routes must carry 404.html's inline-script
    hashes, since spa_fallback serves the 404 document for those paths. Using the
    home page's CSP would block the 404's inline bootstrap (mismatched hashes)."""
    static_root = tmp_path / "static"
    static_root.mkdir()
    # Distinct inline scripts so the home and 404 pages hash differently.
    (static_root / "index.html").write_text(
        "<!doctype html><script>window.__home=1</script>"
    )
    (static_root / "404.html").write_text(
        "<!doctype html><script>window.__notfound=1</script>"
    )
    monkeypatch.setenv("STATIC_ROOT", str(static_root))
    from importlib import reload
    import src.main
    reload(src.main)

    args = src.main._build_security_csp_args()
    by_path = args["html_csp_by_path"]
    assert args["default_html_csp"] == by_path["/404"]
    assert args["default_html_csp"] != by_path["/"]
