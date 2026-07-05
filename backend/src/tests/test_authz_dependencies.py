"""Tests for `Depends(Permission(...))` enforcement.

Mirrors the contract documented in `src/authz/README.md`:

- A permitted role passes the dependency and the route runs.
- A role missing the permission gets a 403.
- Multi-permission `Permission(A, B)` is AND semantics — missing either denies.
- The dependency composes with other `Depends(...)` parameters.
- `app.dependency_overrides[Permission(PERM)] = ...` bypasses the check, and
  finalizers can restore the original behaviour by clearing the entry.
"""
from __future__ import annotations

from typing import Iterator

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS, VIEW_FINDINGS


def _role_to_perms(role: str | None) -> set[str]:
    """Minimal role → permission map for these tests."""
    if role == "admin":
        return {MANAGE_SETTINGS, VIEW_FINDINGS}
    if role == "auditor":
        return {VIEW_FINDINGS}
    return set()


def _make_app(role: str | None) -> FastAPI:
    """Build a fresh app whose middleware injects the given role into request.state."""
    app = FastAPI()

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_role = role
        request.state.user_role_id = None
        return await call_next(request)

    @app.get("/single")
    def single(_: None = Depends(Permission(MANAGE_SETTINGS))) -> dict:
        return {"ok": True}

    @app.get("/multi")
    def multi(_: None = Depends(Permission(MANAGE_SETTINGS, VIEW_FINDINGS))) -> dict:
        return {"ok": True}

    def _provide_value() -> str:
        return "shared-value"

    @app.get("/composed")
    def composed(
        provided: str = Depends(_provide_value),
        _: None = Depends(Permission(MANAGE_SETTINGS)),
    ) -> dict:
        return {"provided": provided}

    return app


@pytest.fixture
def patched_pdp(monkeypatch) -> None:
    """Route the PDP at `has_role_permission` through the role map above."""
    def fake_has_role_permission(role, role_id, permission):
        return permission in _role_to_perms(role)

    monkeypatch.setattr(
        "src.authz.enforcement.dependencies.has_role_permission",
        fake_has_role_permission,
    )


def test_allow_when_user_has_permission(patched_pdp):
    client = TestClient(_make_app(role="admin"))
    resp = client.get("/single")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_deny_when_user_missing_permission(patched_pdp):
    client = TestClient(_make_app(role="auditor"))
    resp = client.get("/single")
    assert resp.status_code == 403
    assert "Permission denied" in resp.json()["detail"]


def test_multi_permission_and_denies_when_either_missing(patched_pdp):
    # auditor has VIEW_FINDINGS but not MANAGE_SETTINGS → denied (AND semantics)
    client = TestClient(_make_app(role="auditor"))
    resp = client.get("/multi")
    assert resp.status_code == 403


def test_multi_permission_and_allows_when_all_present(patched_pdp):
    client = TestClient(_make_app(role="admin"))
    resp = client.get("/multi")
    assert resp.status_code == 200


def test_composes_with_other_dependencies(patched_pdp):
    client = TestClient(_make_app(role="admin"))
    resp = client.get("/composed")
    assert resp.status_code == 200
    assert resp.json() == {"provided": "shared-value"}


def test_composed_route_denies_without_permission(patched_pdp):
    # Composition must still deny — the sibling dependency does not bypass auth.
    client = TestClient(_make_app(role=None))
    resp = client.get("/composed")
    assert resp.status_code == 403


def test_dependency_override_bypasses_check_and_cleanup_restores_it():
    """Dependency-override test pattern with explicit finalizer.

    Two `Permission(MANAGE_SETTINGS)` instances compare equal and hash to the
    same bucket, so the override matches the route's dependency even though
    they were constructed in different places. The cleanup at the end shows
    the canonical fixture-finalizer pattern from the README.
    """
    app = _make_app(role=None)  # role has no permissions → would normally 403
    client = TestClient(app)
    # Sanity: with no override, the route denies.
    assert client.get("/single").status_code == 403

    override_key = Permission(MANAGE_SETTINGS)
    app.dependency_overrides[override_key] = lambda: None
    try:
        resp = client.get("/single")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
    finally:
        app.dependency_overrides.pop(override_key, None)

    # After cleanup, the original guard is back in force.
    assert client.get("/single").status_code == 403


def test_permission_instances_are_equal_and_hashable():
    a = Permission(MANAGE_SETTINGS)
    b = Permission(MANAGE_SETTINGS)
    assert a == b
    assert hash(a) == hash(b)
    # Order matters in the AND-tuple semantics.
    assert Permission(MANAGE_SETTINGS, VIEW_FINDINGS) != Permission(VIEW_FINDINGS, MANAGE_SETTINGS)


def test_permission_requires_at_least_one_arg():
    with pytest.raises(ValueError):
        Permission()


@pytest.fixture
def bypass_manage_settings(patched_pdp) -> Iterator[FastAPI]:
    """Reusable fixture demonstrating the documented finalizer pattern."""
    app = _make_app(role=None)
    key = Permission(MANAGE_SETTINGS)
    app.dependency_overrides[key] = lambda: None
    try:
        yield app
    finally:
        app.dependency_overrides.pop(key, None)


def test_fixture_pattern_bypass(bypass_manage_settings):
    client = TestClient(bypass_manage_settings)
    assert client.get("/single").status_code == 200
