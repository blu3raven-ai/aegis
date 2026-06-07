"""Integration test: middleware stack order is correct after PR 3 cutover."""
from fastapi.testclient import TestClient


def test_security_headers_present_on_every_response():
    """SecurityHeadersMiddleware must run on every response, including healthchecks."""
    from src.main import app
    client = TestClient(app)
    r = client.get("/health/live")
    assert "Content-Security-Policy" in r.headers
    assert "X-Frame-Options" in r.headers
    assert "Strict-Transport-Security" in r.headers


def test_legacy_redirect_runs_before_auth_gate():
    """Legacy URLs redirect even for unauthenticated users (no auth required)."""
    from src.main import app
    client = TestClient(app, follow_redirects=False)
    r = client.get("/settings/sources/code-repositories")
    assert r.status_code == 308
    assert r.headers["location"] == "/sources/code-repositories"


def test_auth_gate_blocks_api_without_cookie():
    """API requests without a session cookie return 401 JSON."""
    from src.main import app
    client = TestClient(app)
    r = client.get("/api/v1/findings")
    assert r.status_code == 401


def test_auth_gate_passes_health_endpoints():
    """Health endpoints are in PUBLIC_PATHS — auth gate must let them through."""
    from src.main import app
    client = TestClient(app)
    r = client.get("/health/live")
    assert r.status_code == 200
    r = client.get("/health/ready")
    assert r.status_code in (200, 503)  # ready may legitimately 503 if deps not up


def test_auth_login_endpoint_reachable_without_session():
    """/auth/login must be public so users can log in."""
    from src.main import app
    client = TestClient(app)
    # POST with no body returns 422 (Pydantic validation), NOT 401
    r = client.post("/auth/login")
    assert r.status_code == 422


def test_trusted_host_blocks_bad_host_header():
    """TrustedHostMiddleware rejects unknown Host headers."""
    from src.main import app
    client = TestClient(app)
    r = client.get("/health/live", headers={"Host": "evil.example.com"})
    assert r.status_code == 400


def test_csp_does_not_contain_unsafe_inline_in_script_src():
    """CSP must use hash-based allow-list, not 'unsafe-inline' (defense in depth)."""
    from src.main import app
    client = TestClient(app)
    r = client.get("/health/live")
    csp = r.headers["Content-Security-Policy"]
    # Parse the script-src section
    script_src_section = next((p for p in csp.split(";") if "script-src" in p), "")
    assert "'unsafe-inline'" not in script_src_section
