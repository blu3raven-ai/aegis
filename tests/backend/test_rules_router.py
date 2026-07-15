"""Router-level tests for the unified Rules CRUD API.

Permissions are short-circuited via patch and the store layer is mocked so
these tests don't need a live DB. This mirrors the lightweight pattern used by
``test_sla_router.py``.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)
os.environ.setdefault("SESSION_SECRET", "test-only-session-secret-not-for-production")

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.rules.router import router as rules_router  # noqa: E402


_ORG = "acme-org"


def _make_app() -> tuple[FastAPI, TestClient]:
    app = FastAPI()
    app.include_router(rules_router)

    @app.middleware("http")
    async def inject_state(request: Request, call_next):
        request.state.user_id = "usr-test"
        request.state.user_email = "test@example.com"
        request.state.user_role = "owner"
        request.state.user_role_id = None
        return await call_next(request)

    return app, TestClient(app, raise_server_exceptions=True)


@contextmanager
def _with_permission(allowed: bool):
    """Patch ``require_permission`` to allow or deny every check."""
    from fastapi import HTTPException

    def _allow(_req, _perm):
        return None

    def _deny(_req, _perm):
        raise HTTPException(status_code=403, detail="denied")

    with patch(
        "src.rules.router.require_permission",
        side_effect=_allow if allowed else _deny,
    ):
        yield


def _sla_rule_dict(**overrides) -> dict:
    base = {
        "id": "sla-abc",
        "org_id": _ORG,
        "category": "sla",
        "name": "Critical 7d",
        "description": None,
        "enabled": True,
        "priority": 10,
        "conditions": {"field": "severity", "op": "eq", "value": "critical"},
        "action": {"deadline_days": 7, "escalations": []},
        "created_by": "test-user",
        "created_at": None,
        "updated_at": None,
        "last_evaluated_at": None,
        "violation_count_open": 0,
        "violation_count_resolved_30d": 0,
    }
    base.update(overrides)
    return base


def _scanner_coverage_rule_dict(**overrides) -> dict:
    base = {
        "id": "scov-abc",
        "org_id": _ORG,
        "category": "scanner_coverage",
        "name": "Production needs all scanners",
        "description": None,
        "enabled": True,
        "priority": 100,
        "conditions": {},
        "action": {
            "type": "require_scanners",
            "required_scanners": ["dependencies_scanning", "code_scanning", "secret_scanning"],
        },
        "created_by": "test-user",
        "created_at": None,
        "updated_at": None,
        "last_evaluated_at": None,
        "violation_count_open": 0,
        "violation_count_resolved_30d": 0,
    }
    base.update(overrides)
    return base


# ── POST /api/v1/rules ────────────────────────────────────────────────────────


def test_create_sla_rule():
    _, client = _make_app()
    body = {
        "org_id": _ORG,
        "category": "sla",
        "name": "Critical 7d",
        "priority": 10,
        "conditions": {"field": "severity", "op": "eq", "value": "critical"},
        "action": {"deadline_days": 7, "escalations": []},
    }
    with _with_permission(True), patch("src.rules.router.store") as mock_store:
        mock_store.create_rule.return_value = _sla_rule_dict()
        resp = client.post("/api/v1/rules", json=body)

    assert resp.status_code == 201
    assert resp.json()["rule"]["category"] == "sla"
    mock_store.create_rule.assert_called_once()


def test_create_scanner_coverage_rule_with_require_scanners_action():
    """scanner_coverage with require_scanners action is accepted."""
    _, client = _make_app()
    body = {
        "org_id": _ORG,
        "category": "scanner_coverage",
        "name": "Production needs all scanners",
        "action": {
            "type": "require_scanners",
            "required_scanners": ["dependencies_scanning", "code_scanning", "secret_scanning"],
        },
    }
    with _with_permission(True), patch("src.rules.router.store") as mock_store:
        mock_store.create_rule.return_value = _scanner_coverage_rule_dict()
        resp = client.post("/api/v1/rules", json=body)
    assert resp.status_code in (200, 201)
    mock_store.create_rule.assert_called_once()


def test_create_scanner_coverage_rule_with_stale_alert_action():
    """scanner_coverage with stale_alert action is accepted."""
    _, client = _make_app()
    body = {
        "org_id": _ORG,
        "category": "scanner_coverage",
        "name": "Stale scan alert",
        "action": {
            "type": "stale_alert",
            "stale_after_days": 14,
            "alert_channel_id": 1,
            "auto_retrigger": False,
        },
    }
    with _with_permission(True), patch("src.rules.router.store") as mock_store:
        mock_store.create_rule.return_value = _scanner_coverage_rule_dict(
            action={
                "type": "stale_alert",
                "stale_after_days": 14,
                "alert_channel_id": 1,
                "auto_retrigger": False,
            },
        )
        resp = client.post("/api/v1/rules", json=body)
    assert resp.status_code in (200, 201)
    mock_store.create_rule.assert_called_once()


def test_create_scanner_coverage_rule_rejects_invalid_action_with_422():
    """A malformed scanner_coverage action (missing type discriminator) is rejected."""
    _, client = _make_app()
    body = {
        "org_id": _ORG,
        "category": "scanner_coverage",
        "name": "Bogus",
        "action": {"required_scanners": ["dependencies_scanning"]},  # missing `type`
    }
    with _with_permission(True), patch("src.rules.router.store") as mock_store:
        resp = client.post("/api/v1/rules", json=body)
    assert resp.status_code == 422
    mock_store.create_rule.assert_not_called()


def test_create_scanner_coverage_rule_requires_manage_permission():
    """scanner_coverage rule creation requires manage_scanner_coverage_rules."""
    _, client = _make_app()
    body = {
        "org_id": _ORG,
        "category": "scanner_coverage",
        "name": "x",
        "action": {"type": "require_scanners", "required_scanners": ["dependencies_scanning"]},
    }
    with _with_permission(False):
        resp = client.post("/api/v1/rules", json=body)
    assert resp.status_code == 403


def test_create_unknown_category_rejected():
    _, client = _make_app()
    body = {
        "org_id": _ORG,
        "category": "bogus",
        "name": "x",
        "action": {},
    }
    with _with_permission(True), patch("src.rules.router.store"):
        resp = client.post("/api/v1/rules", json=body)
    # Pydantic Literal rejects unknown category at request-validation time.
    assert resp.status_code == 422


def test_create_requires_manage_sla_rules_permission():
    _, client = _make_app()
    body = {
        "org_id": _ORG,
        "category": "sla",
        "name": "Critical 7d",
        "action": {"deadline_days": 7},
    }
    with _with_permission(False):
        resp = client.post("/api/v1/rules", json=body)
    assert resp.status_code == 403


def test_create_sla_rule_propagates_created_by_from_request_state():
    _, client = _make_app()
    body = {
        "org_id": _ORG,
        "category": "sla",
        "name": "Critical 7d",
        "priority": 10,
        "conditions": {"field": "severity", "op": "eq", "value": "critical"},
        "action": {"deadline_days": 7, "escalations": []},
    }
    with _with_permission(True), patch("src.rules.router.store") as mock_store:
        mock_store.create_rule.return_value = _sla_rule_dict()
        client.post("/api/v1/rules", json=body)
        mock_store.create_rule.assert_called_once()
        kwargs = mock_store.create_rule.call_args.kwargs
        assert kwargs["created_by"] == "usr-test"
        assert kwargs["category"] == "sla"
        assert kwargs["name"] == "Critical 7d"


def test_create_sla_rule_returns_401_when_user_identity_missing():
    app = FastAPI()
    app.include_router(rules_router)

    @app.middleware("http")
    async def empty_state(request: Request, call_next):
        request.state.user_role = "owner"
        request.state.user_role_id = None
        # intentionally NO user_id and NO user_email
        return await call_next(request)

    client = TestClient(app, raise_server_exceptions=True)

    with _with_permission(True), patch("src.rules.router.store") as mock_store:
        resp = client.post("/api/v1/rules", json={
            "org_id": _ORG,
            "category": "sla",
            "name": "Critical 7d",
            "action": {"deadline_days": 7, "escalations": []},
        })

    assert resp.status_code == 401
    mock_store.create_rule.assert_not_called()


def test_create_sla_rule_rejects_invalid_action_with_422():
    _, client = _make_app()
    with _with_permission(True), patch("src.rules.router.store") as mock_store:
        resp = client.post("/api/v1/rules", json={
            "org_id": _ORG,
            "category": "sla",
            "name": "Critical 0d",
            "action": {"deadline_days": 0, "escalations": []},
        })
    assert resp.status_code == 422
    mock_store.create_rule.assert_not_called()


# ── GET /api/v1/rules/{rule_id} ───────────────────────────────────────────────


def test_get_rule_requires_view_rules_permission():
    _, client = _make_app()
    with _with_permission(False):
        resp = client.get("/api/v1/rules/sla-abc", params={"org_id": _ORG})
    assert resp.status_code == 403


# ── PUT /api/v1/rules/{rule_id} ───────────────────────────────────────────────


def test_update_rule_silently_drops_category_field():
    """Pydantic ``RuleUpdate`` doesn't define ``category`` — but it isn't
    ``extra='forbid'`` either. The router pulls fields via
    ``model_dump(exclude_unset=True)`` so an unknown key is silently dropped.
    This test pins that behaviour: an attempt to PUT ``category`` succeeds at
    the API surface but never reaches the store as a category change.
    """
    _, client = _make_app()
    existing = _sla_rule_dict()
    updated = _sla_rule_dict(name="New name")
    with _with_permission(True), patch("src.rules.router.store") as mock_store:
        mock_store.get_rule_by_id.return_value = existing
        mock_store.update_rule.return_value = updated
        resp = client.put(
            "/api/v1/rules/sla-abc",
            params={"org_id": _ORG},
            json={"name": "New name", "category": "auto_dismiss"},
        )

    assert resp.status_code == 200
    _, kwargs = mock_store.update_rule.call_args
    assert "category" not in kwargs
    assert kwargs == {"name": "New name"}


def test_update_rule_partial_update_preserves_unset_fields():
    _, client = _make_app()
    existing = _sla_rule_dict()
    updated = _sla_rule_dict(name="Renamed")
    with _with_permission(True), patch("src.rules.router.store") as mock_store:
        mock_store.get_rule_by_id.return_value = existing
        mock_store.update_rule.return_value = updated
        resp = client.put(
            "/api/v1/rules/sla-abc",
            params={"org_id": _ORG},
            json={"name": "Renamed"},
        )

    assert resp.status_code == 200
    _, kwargs = mock_store.update_rule.call_args
    assert kwargs == {"name": "Renamed"}


def test_update_rule_requires_manage_sla_rules_permission():
    """PUT does a two-stage permission check: view_rules first, then
    manage_sla_rules after the rule is fetched. Cover the middle case where
    view is allowed but manage is denied.
    """
    _, client = _make_app()
    from fastapi import HTTPException

    def _selective(_req, perm):
        if perm == "view_rules":
            return
        raise HTTPException(status_code=403, detail="manage denied")

    with patch("src.rules.router.require_permission", side_effect=_selective), \
         patch("src.rules.router.store") as mock_store:
        mock_store.get_rule_by_id.return_value = _sla_rule_dict()
        resp = client.put(
            "/api/v1/rules/sla-abc",
            params={"org_id": _ORG},
            json={"name": "renamed"},
        )

    assert resp.status_code == 403
    mock_store.update_rule.assert_not_called()


def test_update_rule_rejects_invalid_action_with_422():
    _, client = _make_app()
    with _with_permission(True), patch("src.rules.router.store") as mock_store:
        mock_store.get_rule_by_id.return_value = _sla_rule_dict()
        resp = client.put(
            "/api/v1/rules/sla-abc",
            params={"org_id": _ORG},
            json={"action": {"deadline_days": 0, "escalations": []}},
        )
    assert resp.status_code == 422
    mock_store.update_rule.assert_not_called()


# ── DELETE /api/v1/rules/{rule_id} ────────────────────────────────────────────


def test_delete_rule():
    _, client = _make_app()
    with _with_permission(True), patch("src.rules.router.store") as mock_store:
        mock_store.get_rule_by_id.return_value = _sla_rule_dict()
        mock_store.delete_rule.return_value = True
        resp = client.delete("/api/v1/rules/sla-abc", params={"org_id": _ORG})

    assert resp.status_code == 204


def test_delete_rule_requires_manage_sla_rules_permission():
    """DELETE: view_rules allowed, manage_sla_rules denied → 403."""
    _, client = _make_app()
    from fastapi import HTTPException

    def _selective(_req, perm):
        if perm == "view_rules":
            return
        raise HTTPException(status_code=403, detail="manage denied")

    with patch("src.rules.router.require_permission", side_effect=_selective), \
         patch("src.rules.router.store") as mock_store:
        mock_store.get_rule_by_id.return_value = _sla_rule_dict()
        resp = client.delete("/api/v1/rules/sla-abc", params={"org_id": _ORG})

    assert resp.status_code == 403
    mock_store.delete_rule.assert_not_called()


# ── POST /api/v1/rules/{rule_id}/toggle ───────────────────────────────────────


def test_toggle_rule():
    _, client = _make_app()
    with _with_permission(True), patch("src.rules.router.store") as mock_store:
        mock_store.get_rule_by_id.return_value = _sla_rule_dict()
        mock_store.toggle_rule.return_value = _sla_rule_dict(enabled=False)
        resp = client.post("/api/v1/rules/sla-abc/toggle", params={"org_id": _ORG})

    assert resp.status_code == 200
    assert resp.json()["rule"]["enabled"] is False


def test_toggle_rule_requires_manage_sla_rules_permission():
    """POST /toggle: view_rules allowed, manage_sla_rules denied → 403."""
    _, client = _make_app()
    from fastapi import HTTPException

    def _selective(_req, perm):
        if perm == "view_rules":
            return
        raise HTTPException(status_code=403, detail="manage denied")

    with patch("src.rules.router.require_permission", side_effect=_selective), \
         patch("src.rules.router.store") as mock_store:
        mock_store.get_rule_by_id.return_value = _sla_rule_dict()
        resp = client.post("/api/v1/rules/sla-abc/toggle", params={"org_id": _ORG})

    assert resp.status_code == 403
    mock_store.toggle_rule.assert_not_called()


