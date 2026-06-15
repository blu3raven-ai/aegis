"""Tests for the public /api/v1/branding endpoint (no auth)."""
from __future__ import annotations

from fastapi.testclient import TestClient

from src.main import app


def test_public_branding_returns_null_for_fresh_install():
    """Fresh install: name + logo are NULL. Clients own the vendor fallback."""
    client = TestClient(app)
    resp = client.get("/api/v1/branding")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] is None
    assert "logoDataUrl" in body
    assert body["logoDataUrl"] is None


def test_public_branding_does_not_leak_other_fields():
    client = TestClient(app)
    body = client.get("/api/v1/branding").json()
    # Only the two branding fields are exposed; no PII or other org settings.
    assert set(body.keys()) == {"name", "logoDataUrl"}
