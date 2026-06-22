"""Tests for the rules read endpoints under /api/v1/rules.

Covers the 5 GET handlers migrated from GraphQL back to REST:

  - GET /
  - GET /summary
  - GET /kill-switches
  - GET /{rule_id}
  - GET /{rule_id}/violations

Rules are org-wide so the handlers gate solely on ``VIEW_RULES`` and skip
the asset-scope step; the matching cross-scope keystone test on the
compliance suite has no equivalent here.
"""
from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import VIEW_RULES  # noqa: E402
from src.rules.router import VIOLATIONS_MAX_LIMIT, router as rules_router  # noqa: E402


_VIEWER_PERMS = {"view_rules"}
_NO_PERMS: set[str] = set()


def _make_app(*, allow_view_rules: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(rules_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "viewer-1"
        request.state.user_id = "viewer-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_view_rules:
        app.dependency_overrides[Permission(VIEW_RULES)] = lambda: None
    return app


def _rule_row(
    *,
    rule_id: str = "sla-abc",
    category: str = "sla",
    name: str = "Critical SLA",
    enabled: bool = True,
) -> dict:
    return {
        "id": rule_id,
        "category": category,
        "name": name,
        "description": "fix criticals fast",
        "enabled": enabled,
        "priority": 100,
        "conditions": {"field": "severity", "op": "eq", "value": "critical"},
        "action": {"deadline_days": 7, "escalations": []},
        "created_by": "u-1",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-02T00:00:00+00:00",
        "last_evaluated_at": None,
        "violation_count_open": 0,
        "violation_count_resolved_30d": 0,
    }


def _violation_row(*, vid: int = 1, rule_id: str = "sla-abc") -> dict:
    return {
        "id": vid,
        "rule_id": rule_id,
        "subject_type": "finding",
        "subject_id": f"f-{vid}",
        "status": "open",
        "opened_at": "2026-06-01T00:00:00+00:00",
        "resolved_at": None,
        "context": {"severity": "critical"},
    }


def _kill_switch_row(*, ks_id: int = 1, category: str = "auto_dismiss") -> dict:
    return {
        "id": ks_id,
        "category": category,
        "killed_at": "2026-06-10T00:00:00+00:00",
        "killed_by": "admin-1",
        "reason": "test pause",
    }


# ── GET / (list_rules_handler) ────────────────────────────────────────────


def test_list_rules_returns_envelope_with_rows():
    rows = [_rule_row(rule_id="sla-abc"), _rule_row(rule_id="sla-def", name="High SLA")]
    with (
        patch("src.rules.router.store.list_rules", return_value=rows) as mock_store,
    ):
        resp = TestClient(_make_app()).get("/api/v1/rules")

    assert resp.status_code == 200
    body = resp.json()
    assert list(body.keys()) == ["rules"]
    assert len(body["rules"]) == 2
    assert body["rules"][0]["id"] == "sla-abc"
    assert body["rules"][1]["name"] == "High SLA"
    mock_store.assert_called_once_with(category=None, enabled=None, q=None)


def test_list_rules_passes_category_to_store():
    with (
        patch("src.rules.router.store.list_rules", return_value=[]) as mock_store,
    ):
        resp = TestClient(_make_app()).get("/api/v1/rules?category=sla")

    assert resp.status_code == 200
    assert resp.json() == {"rules": []}
    mock_store.assert_called_once_with(category="sla", enabled=None, q=None)


def test_list_rules_passes_enabled_bool_to_store():
    with (
        patch("src.rules.router.store.list_rules", return_value=[]) as mock_store,
    ):
        resp = TestClient(_make_app()).get("/api/v1/rules?enabled=true")

    assert resp.status_code == 200
    assert resp.json() == {"rules": []}
    mock_store.assert_called_once_with(category=None, enabled=True, q=None)


def test_list_rules_passes_search_q_to_store():
    with (
        patch("src.rules.router.store.list_rules", return_value=[]) as mock_store,
    ):
        resp = TestClient(_make_app()).get("/api/v1/rules?q=acme")

    assert resp.status_code == 200
    assert resp.json() == {"rules": []}
    mock_store.assert_called_once_with(category=None, enabled=None, q="acme")


def test_list_rules_forbidden_without_view_rules():
    with (
        patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False),
        patch("src.rules.router.store.list_rules") as mock_store,
    ):
        resp = TestClient(_make_app(allow_view_rules=False)).get("/api/v1/rules")

    assert resp.status_code == 403
    mock_store.assert_not_called()


# ── GET /summary (get_rule_summary_handler) ───────────────────────────────


def test_get_rule_summary_returns_envelope():
    payload = {
        "active_rules": 12,
        "violations_open": 5,
        "coverage_gaps": 2,
        "sla_compliance_pct": 88.5,
    }
    with (
        patch("src.rules.router.store.summary", return_value=payload),
    ):
        resp = TestClient(_make_app()).get("/api/v1/rules/summary")

    assert resp.status_code == 200
    assert resp.json() == payload


def test_get_rule_summary_forbidden_without_view_rules():
    with (
        patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False),
        patch("src.rules.router.store.summary") as mock_store,
    ):
        resp = TestClient(_make_app(allow_view_rules=False)).get("/api/v1/rules/summary")

    assert resp.status_code == 403
    mock_store.assert_not_called()


# ── GET /kill-switches (list_kill_switches_handler) ───────────────────────


def test_list_kill_switches_returns_envelope_with_rows():
    rows = [_kill_switch_row(), _kill_switch_row(ks_id=2, category="data_retention")]
    with (
        patch("src.rules.router.store.list_kill_switches", return_value=rows),
    ):
        resp = TestClient(_make_app()).get("/api/v1/rules/kill-switches")

    assert resp.status_code == 200
    body = resp.json()
    assert list(body.keys()) == ["kill_switches"]
    assert len(body["kill_switches"]) == 2
    assert body["kill_switches"][0]["category"] == "auto_dismiss"
    assert body["kill_switches"][1]["category"] == "data_retention"


def test_list_kill_switches_empty_returns_empty_envelope():
    with (
        patch("src.rules.router.store.list_kill_switches", return_value=[]),
    ):
        resp = TestClient(_make_app()).get("/api/v1/rules/kill-switches")

    assert resp.status_code == 200
    assert resp.json() == {"kill_switches": []}


def test_list_kill_switches_forbidden_without_view_rules():
    with (
        patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False),
        patch("src.rules.router.store.list_kill_switches") as mock_store,
    ):
        resp = TestClient(_make_app(allow_view_rules=False)).get("/api/v1/rules/kill-switches")

    assert resp.status_code == 403
    mock_store.assert_not_called()


# ── GET /{rule_id} (get_rule_handler) ─────────────────────────────────────


def test_get_rule_returns_envelope():
    row = _rule_row(rule_id="sla-abc")
    with (
        patch("src.rules.router.store.get_rule_by_id", return_value=row) as mock_store,
    ):
        resp = TestClient(_make_app()).get("/api/v1/rules/sla-abc")

    assert resp.status_code == 200
    body = resp.json()
    assert list(body.keys()) == ["rule"]
    assert body["rule"]["id"] == "sla-abc"
    assert body["rule"]["category"] == "sla"
    mock_store.assert_called_once_with("sla-abc")


def test_get_rule_unknown_id_returns_404():
    with (
        patch("src.rules.router.store.get_rule_by_id", return_value=None),
    ):
        resp = TestClient(_make_app()).get("/api/v1/rules/nonexistent")

    assert resp.status_code == 404
    assert resp.json()["detail"] == "rule not found"


def test_get_rule_forbidden_without_view_rules():
    with (
        patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False),
        patch("src.rules.router.store.get_rule_by_id") as mock_store,
    ):
        resp = TestClient(_make_app(allow_view_rules=False)).get("/api/v1/rules/sla-abc")

    assert resp.status_code == 403
    mock_store.assert_not_called()


# ── GET /{rule_id}/violations (list_rule_violations_handler) ──────────────


def test_list_rule_violations_returns_envelope():
    page = {
        "violations": [_violation_row(vid=1), _violation_row(vid=2)],
        "total": 2,
        "limit": 50,
        "offset": 0,
    }
    with (
        patch("src.rules.router.store.list_violations_for_rule", return_value=page) as mock_store,
    ):
        resp = TestClient(_make_app()).get("/api/v1/rules/sla-abc/violations")

    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert len(body["violations"]) == 2
    mock_store.assert_called_once_with("sla-abc", limit=50, offset=0)


def test_list_rule_violations_passes_limit_offset_to_store():
    page = {"violations": [], "total": 0, "limit": 10, "offset": 5}
    with (
        patch("src.rules.router.store.list_violations_for_rule", return_value=page) as mock_store,
    ):
        resp = TestClient(_make_app()).get(
            "/api/v1/rules/sla-abc/violations?limit=10&offset=5",
        )

    assert resp.status_code == 200
    mock_store.assert_called_once_with("sla-abc", limit=10, offset=5)


def test_list_rule_violations_clamps_limit_above_max():
    page = {"violations": [], "total": 0, "limit": VIOLATIONS_MAX_LIMIT, "offset": 0}
    with (
        patch("src.rules.router.store.list_violations_for_rule", return_value=page) as mock_store,
    ):
        resp = TestClient(_make_app()).get(
            "/api/v1/rules/sla-abc/violations?limit=999",
        )

    assert resp.status_code == 200
    mock_store.assert_called_once_with("sla-abc", limit=VIOLATIONS_MAX_LIMIT, offset=0)


def test_list_rule_violations_clamps_limit_below_one():
    page = {"violations": [], "total": 0, "limit": 1, "offset": 0}
    with (
        patch("src.rules.router.store.list_violations_for_rule", return_value=page) as mock_store,
    ):
        resp = TestClient(_make_app()).get(
            "/api/v1/rules/sla-abc/violations?limit=0",
        )

    assert resp.status_code == 200
    mock_store.assert_called_once_with("sla-abc", limit=1, offset=0)


def test_list_rule_violations_unknown_rule_returns_empty_page():
    # Mirrors the store's fail-soft: unknown ruleId returns an empty page
    # rather than a 404 because callers were about to render an empty list.
    page = {"violations": [], "total": 0, "limit": 50, "offset": 0}
    with (
        patch("src.rules.router.store.list_violations_for_rule", return_value=page),
    ):
        resp = TestClient(_make_app()).get("/api/v1/rules/nonexistent/violations")

    assert resp.status_code == 200
    assert resp.json() == {"violations": [], "total": 0, "limit": 50, "offset": 0}


def test_list_rule_violations_forbidden_without_view_rules():
    with (
        patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False),
        patch("src.rules.router.store.list_violations_for_rule") as mock_store,
    ):
        resp = TestClient(_make_app(allow_view_rules=False)).get("/api/v1/rules/sla-abc/violations")

    assert resp.status_code == 403
    mock_store.assert_not_called()
