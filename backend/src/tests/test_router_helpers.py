"""Contract tests for the shared router helpers.

filter_by_user_scope is a BOLA scope gate (admins see everything; others only
items for repos they can access), so its allow/deny logic is security-relevant.
Also covers require_orgs parsing, validate_org's 403 gate, and api_error.
"""
from __future__ import annotations

import json

import pytest
from fastapi import HTTPException

from src.shared import router_helpers as rh
from src.shared.router_helpers import api_error, filter_by_user_scope, require_orgs, validate_org


_REQ = object()  # request is only passed to mocked authz helpers


# ----- require_orgs ---------------------------------------------------------

def test_require_orgs_parses_and_dedupes():
    assert require_orgs(["acme"]) == ["acme"]
    assert require_orgs(["a, b", "A"]) == ["a", "b"]  # CSV split + case-insensitive dedup


def test_require_orgs_rejects_empty():
    with pytest.raises(HTTPException) as exc:
        require_orgs([])
    assert exc.value.status_code == 400


# ----- filter_by_user_scope -------------------------------------------------

def test_admin_sees_all_items(monkeypatch):
    monkeypatch.setattr(rh, "has_permission", lambda req, perm: True)
    items = [{"organization": "acme", "repository": "api"}, {"organization": "x", "repository": "y"}]
    assert filter_by_user_scope(_REQ, items) == items


def test_non_admin_filtered_to_accessible_repos(monkeypatch):
    monkeypatch.setattr(rh, "has_permission", lambda req, perm: False)
    monkeypatch.setattr(rh, "actor_user_id", lambda req: "u1")
    monkeypatch.setattr(rh, "list_teams", lambda: [])
    monkeypatch.setattr(rh, "list_direct_grants", lambda: [])
    # Access only to acme/api.
    monkeypatch.setattr(
        rh, "user_has_repository_access",
        lambda teams, uid, org, repo, direct_grants: org == "acme" and repo == "api",
    )
    items = [
        {"organization": "acme", "repository": "api"},   # allowed
        {"organization": "acme", "repository": "web"},   # denied
        {"organization": "other", "repository": "api"},  # denied
    ]
    assert filter_by_user_scope(_REQ, items) == [{"organization": "acme", "repository": "api"}]


def test_filter_honours_custom_keys_and_missing_values(monkeypatch):
    monkeypatch.setattr(rh, "has_permission", lambda req, perm: False)
    monkeypatch.setattr(rh, "actor_user_id", lambda req: "u1")
    monkeypatch.setattr(rh, "list_teams", lambda: [])
    monkeypatch.setattr(rh, "list_direct_grants", lambda: [])
    seen = []

    def fake_access(teams, uid, org, repo, direct_grants):
        seen.append((org, repo))
        return org == "acme"

    monkeypatch.setattr(rh, "user_has_repository_access", fake_access)
    items = [{"myorg": "acme", "myrepo": "api"}, {"nope": 1}]
    out = filter_by_user_scope(_REQ, items, org_key="myorg", repo_key="myrepo")
    assert out == [{"myorg": "acme", "myrepo": "api"}]
    # Missing keys coerce to empty strings, never None.
    assert ("", "") in seen


# ----- validate_org ---------------------------------------------------------

def test_validate_org_allows_known_and_403s_unknown(monkeypatch):
    monkeypatch.setattr("src.shared.config.get_orgs_from_source_connections", lambda: ["acme"])
    validate_org("acme")  # no raise
    with pytest.raises(HTTPException) as exc:
        validate_org("ghost")
    assert exc.value.status_code == 403


# ----- api_error ------------------------------------------------------------

def test_api_error_shape():
    resp = api_error("boom", 500)
    assert resp.status_code == 500
    assert json.loads(resp.body) == {"error": "boom"}
