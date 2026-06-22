"""Tests for the public OrgBranding GQL query (no auth required)."""
from __future__ import annotations

from fastapi.testclient import TestClient

from src.main import app

_Q_ORG_BRANDING = "query OrgBranding { orgBranding { name logoDataUrl updatedAt } }"


def _public_gql(query: str, operation_name: str) -> dict:
    client = TestClient(app)
    resp = client.post(
        "/api/v1/graphql",
        json={"operationName": operation_name, "query": query},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_public_org_returns_null_for_fresh_install():
    """Fresh install: name + logo are NULL. Clients own the vendor fallback."""
    body = _public_gql(_Q_ORG_BRANDING, "OrgBranding")
    data = body["data"]["orgBranding"]
    assert data["name"] is None
    assert "logoDataUrl" in data
    assert data["logoDataUrl"] is None


def test_public_org_does_not_leak_other_fields():
    body = _public_gql(_Q_ORG_BRANDING, "OrgBranding")
    data = body["data"]["orgBranding"]
    # Only the canonical org-identity fields are exposed; no PII or other org settings.
    assert set(data.keys()) == {"name", "logoDataUrl", "updatedAt"}
