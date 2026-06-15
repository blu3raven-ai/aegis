"""Tests for SecurityHeadersMiddleware headers and CSP composition."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.auth.security_headers import SecurityHeadersMiddleware

# Valid 44-char base64-encoded SHA-256 placeholders (43 base64 chars + '=').
_HASH_A = "A" * 43 + "="
_HASH_B = "B" * 43 + "="


def _app(script_hashes: list[str] | None = None):
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware, script_hashes=script_hashes or [])

    @app.get("/")
    def home():
        return {"ok": True}

    @app.get("/docs")
    def docs():
        return {"ok": True}

    @app.get("/docs/oauth2-redirect")
    def docs_oauth():
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


def test_csp_contains_strict_dynamic_when_hashes_present():
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "'strict-dynamic'" in csp


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


def test_non_docs_path_keeps_strict_csp():
    """Carve-out must not leak to other routes."""
    client = TestClient(_app(script_hashes=[_HASH_A]))
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "require-trusted-types-for" in csp
    assert "'strict-dynamic'" in csp
    # Strict script-src has only 'self' + strict-dynamic + hashes, no 'unsafe-inline'.
    script_src = next(p for p in csp.split(";") if "script-src" in p)
    assert "'unsafe-inline'" not in script_src
