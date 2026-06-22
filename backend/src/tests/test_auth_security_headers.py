"""Tests for SecurityHeadersMiddleware headers and CSP composition."""
import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from src.auth.authentication.security_headers import SecurityHeadersMiddleware, _build_csp, _resolve_html_csp

# Valid 44-char base64-encoded SHA-256 placeholders (43 base64 chars + '=').
_HASH_A = "A" * 43 + "="
_HASH_B = "B" * 43 + "="


def _app(script_hashes: list[str] | None = None):
    # The strict per-page policy is what "/" (an HTML document) receives;
    # non-HTML routes get the script-less base policy.
    page_csp = _build_csp(script_hashes or [])
    app = FastAPI()
    app.add_middleware(
        SecurityHeadersMiddleware,
        html_csp_by_path={"/": page_csp},
        default_html_csp=page_csp,
        base_csp=_build_csp([]),
    )

    @app.get("/")
    def home():
        return HTMLResponse("<html></html>")

    @app.get("/api/data")
    def api_data():
        return {"ok": True}

    @app.get("/sources/123")
    def spa_route():
        # An HTML route not in the map — should fall back to default_html_csp.
        return HTMLResponse("<html></html>")

    @app.get("/docs")
    def docs():
        return {"ok": True}

    @app.get("/docs/oauth2-redirect")
    def docs_oauth():
        return {"ok": True}

    @app.get("/api/v1/graphql")
    def graphql():
        return {"ok": True}

    return app


def test_response_has_hsts():
    client = TestClient(_app())
    r = client.get("/")
    hsts = r.headers["Strict-Transport-Security"]
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts


def test_response_has_xfo_deny():
    client = TestClient(_app())
    r = client.get("/")
    assert r.headers["X-Frame-Options"] == "DENY"


def test_response_has_xcto_nosniff():
    client = TestClient(_app())
    r = client.get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_response_has_referrer_policy():
    client = TestClient(_app())
    r = client.get("/")
    assert r.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_response_has_permissions_policy():
    client = TestClient(_app())
    r = client.get("/")
    perms = r.headers["Permissions-Policy"]
    assert "camera=()" in perms
    assert "microphone=()" in perms
    assert "geolocation=()" in perms


def test_csp_does_not_contain_unsafe_inline_in_script_src():
    client = TestClient(_app(script_hashes=[_HASH_A, _HASH_B]))
    csp = client.get("/").headers["Content-Security-Policy"]
    script_src_section = next(p for p in csp.split(";") if "script-src" in p)
    assert "'unsafe-inline'" not in script_src_section


def test_csp_contains_script_hashes():
    client = TestClient(_app(script_hashes=[_HASH_A, _HASH_B]))
    csp = client.get("/").headers["Content-Security-Policy"]
    assert f"'sha256-{_HASH_A}'" in csp
    assert f"'sha256-{_HASH_B}'" in csp


def test_csp_uses_self_not_strict_dynamic():
    """Static export cannot emit per-request nonces, so the policy must rely on
    'self' for same-origin chunks rather than 'strict-dynamic' (which would make
    the browser ignore 'self' and block every parser-inserted <script src>)."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/").headers["Content-Security-Policy"]
    script_src = next(p for p in csp.split(";") if "script-src" in p)
    assert "'self'" in script_src
    assert "'strict-dynamic'" not in csp


def test_csp_blocks_dangerous_defaults():
    client = TestClient(_app())
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "form-action 'self'" in csp


def test_csp_raises_on_invalid_hash_format():
    """Defense-in-depth: malformed hashes are rejected at construction.

    Starlette initialises middleware lazily on the first request, so the
    ValueError surfaces when TestClient makes its first call.
    """
    with pytest.raises(ValueError, match="invalid script hash format"):
        TestClient(_app(script_hashes=["not-a-base64-sha256"])).get("/")


def test_csp_raises_on_empty_hash():
    with pytest.raises(ValueError, match="invalid script hash format"):
        TestClient(_app(script_hashes=[""])).get("/")


def test_csp_accepts_valid_base64_sha256_hash():
    """44-char base64 SHA-256: 43 base64 chars + 1 '='."""
    valid = "A" * 43 + "="
    # Should not raise
    client = TestClient(_app(script_hashes=[valid]))
    assert client.get("/").status_code == 200


def test_docs_csp_allows_inline_for_swagger_ui():
    """Swagger UI ships an inline init script — needs 'unsafe-inline' on script-src."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/docs").headers["Content-Security-Policy"]
    script_src = next(p for p in csp.split(";") if "script-src" in p)
    style_src = next(p for p in csp.split(";") if "style-src" in p)
    assert "'unsafe-inline'" in script_src
    assert "'unsafe-inline'" in style_src


def test_docs_csp_has_no_external_host_allowlist():
    """Assets are self-hosted at /swagger — no external origin should be trusted."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/docs").headers["Content-Security-Policy"]
    assert "cdn.jsdelivr.net" not in csp


def test_docs_csp_drops_trusted_types_and_strict_dynamic():
    """Swagger UI uses innerHTML and inline init — Trusted Types + strict-dynamic block it."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/docs").headers["Content-Security-Policy"]
    assert "require-trusted-types-for" not in csp
    assert "'strict-dynamic'" not in csp


def test_docs_subpath_gets_docs_csp():
    """/docs/oauth2-redirect and similar sub-routes must also relax CSP."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/docs/oauth2-redirect").headers["Content-Security-Policy"]
    script_src = next(p for p in csp.split(";") if "script-src" in p)
    assert "'unsafe-inline'" in script_src


def test_graphiql_csp_allows_unpkg_cdn():
    """GraphiQL bundles React + js-cookie + graphiql from unpkg.com."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/api/v1/graphql").headers["Content-Security-Policy"]
    script_src = next(p for p in csp.split(";") if "script-src" in p)
    style_src = next(p for p in csp.split(";") if "style-src" in p)
    assert "https://unpkg.com" in script_src
    assert "'unsafe-inline'" in script_src
    assert "https://unpkg.com" in style_src


def test_graphiql_csp_drops_trusted_types_and_strict_dynamic():
    """GraphiQL's inline init script can't satisfy strict-dynamic + Trusted Types."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/api/v1/graphql").headers["Content-Security-Policy"]
    assert "require-trusted-types-for" not in csp
    assert "'strict-dynamic'" not in csp


def test_graphiql_csp_does_not_apply_to_other_routes():
    """The unpkg.com allowance must stay scoped to /api/v1/graphql."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "unpkg.com" not in csp


def test_non_docs_path_keeps_strict_csp():
    """Carve-out must not leak to other routes."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "object-src 'none'" in csp
    # Strict script-src is 'self' + hashes, no 'unsafe-inline'.
    script_src = next(p for p in csp.split(";") if "script-src" in p)
    assert "'self'" in script_src
    assert "'unsafe-inline'" not in script_src


def test_csp_does_not_enforce_trusted_types():
    """React writes innerHTML without a TrustedHTML, so enforcing Trusted Types
    crashes rendering — the directive must not be present."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "require-trusted-types-for" not in csp


def test_html_document_gets_page_specific_hashes():
    """An HTML document must carry its own script hashes so inline Next.js
    bootstrap / hydration scripts are allowed to execute."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    r = client.get("/")
    assert "text/html" in r.headers["content-type"]
    assert f"'sha256-{_HASH_A}'" in r.headers["Content-Security-Policy"]


def test_non_html_response_gets_scriptless_csp():
    """JSON/API responses run no inline scripts — they get the minimal policy,
    keeping the header small and without strict-dynamic or hashes."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/api/data").headers["Content-Security-Policy"]
    script_src = next(p for p in csp.split(";") if "script-src" in p)
    assert script_src.strip() == "script-src 'self'"
    assert "'strict-dynamic'" not in csp
    assert f"'sha256-{_HASH_A}'" not in csp


def test_unmapped_html_route_falls_back_to_default_html_csp():
    """SPA routes that resolve to index.html get the default HTML policy
    (which carries the shell's script hashes), not the script-less base."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/sources/123").headers["Content-Security-Policy"]
    script_src = next(p for p in csp.split(";") if "script-src" in p)
    assert "'self'" in script_src
    assert f"'sha256-{_HASH_A}'" in csp


# ---------------------------------------------------------------------------
# _resolve_html_csp — stub substitution for dynamic routes
# ---------------------------------------------------------------------------

def test_resolve_html_csp_exact_match():
    by_path = {"/sources/_": "csp-stub", "/": "csp-home"}
    assert _resolve_html_csp("/sources/_", by_path, "default") == "csp-stub"


def test_resolve_html_csp_stub_substitution_leaf():
    """'/sources/abc123' resolves via '/sources/_' when that stub is in the map."""
    by_path = {"/sources/_": "csp-sources-stub", "/": "csp-home"}
    assert _resolve_html_csp("/sources/abc123", by_path, "default") == "csp-sources-stub"


def test_resolve_html_csp_stub_substitution_nested():
    """'/sources/abc/findings' resolves via '/sources/_/findings'."""
    by_path = {"/sources/_/findings": "csp-findings-stub", "/": "csp-home"}
    assert _resolve_html_csp("/sources/abc/findings", by_path, "default") == "csp-findings-stub"


def test_resolve_html_csp_falls_back_to_default_when_no_stub():
    """Falls back to the default when no stub matches any segment."""
    by_path = {"/": "csp-home"}
    assert _resolve_html_csp("/some/unknown/route", by_path, "default") == "default"


def test_resolve_html_csp_exact_wins_over_stub():
    """An exact path match beats a stub match for the same level."""
    by_path = {"/sources/known": "csp-exact", "/sources/_": "csp-stub"}
    assert _resolve_html_csp("/sources/known", by_path, "default") == "csp-exact"
