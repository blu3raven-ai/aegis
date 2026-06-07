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


def test_static_index_html_served_at_root(tmp_path, monkeypatch):
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("<!doctype html><title>aegis</title>")
    client = _client(monkeypatch, static_root)
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


def test_unknown_spa_route_falls_back_to_index_html(tmp_path, monkeypatch):
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("<!doctype html><title>spa</title>")
    client = _client(monkeypatch, static_root)
    r = client.get("/secrets/dashboard")
    assert r.status_code == 200
    assert "<title>spa</title>" in r.text


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
