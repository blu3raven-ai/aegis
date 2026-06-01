"""Router-level tests for SLA policy CRUD and breach summary endpoints.

Permissions are short-circuited via patch so these tests don't need a live DB.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from unittest.mock import patch, MagicMock

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SHARED_SECRET", "0" * 64)

from src.sla.router import router as sla_router  # noqa: E402


def _make_app() -> tuple[FastAPI, TestClient]:
    app = FastAPI()
    app.include_router(sla_router)

    @app.middleware("http")
    async def inject_state(request: Request, call_next):
        request.state.user_sub = "test-user"
        request.state.user_role = "owner"
        request.state.user_role_id = None
        return await call_next(request)

    client = TestClient(app, raise_server_exceptions=True)
    return app, client


@contextmanager
def _with_permission(allowed: bool):
    """Patch require_permission to allow or deny."""
    from fastapi import HTTPException

    def _allow(_req, _perm):
        pass

    def _deny(_req, _perm):
        raise HTTPException(status_code=403, detail="Permission denied")

    with patch("src.sla.router.require_permission", side_effect=_allow if allowed else _deny):
        yield


MOCK_POLICIES = [
    {"id": 1, "org_id": "acme-org", "severity": "critical", "deadline_days": 7, "enabled": True, "created_at": None, "updated_at": None},
    {"id": 2, "org_id": "acme-org", "severity": "high", "deadline_days": 14, "enabled": True, "created_at": None, "updated_at": None},
    {"id": 3, "org_id": "acme-org", "severity": "medium", "deadline_days": 30, "enabled": True, "created_at": None, "updated_at": None},
    {"id": 4, "org_id": "acme-org", "severity": "low", "deadline_days": 90, "enabled": True, "created_at": None, "updated_at": None},
]

MOCK_SUMMARY = {
    "critical": {"open": 5, "breached": 2, "breached_pct": 0.4},
    "high": {"open": 10, "breached": 1, "breached_pct": 0.1},
    "medium": {"open": 20, "breached": 0, "breached_pct": 0.0},
    "low": {"open": 3, "breached": 0, "breached_pct": 0.0},
}


# ── GET /api/v1/sla-policies ──────────────────────────────────────────────────

def test_list_policies_returns_four_entries():
    _, client = _make_app()
    with patch("src.sla.router.get_sla_service") as mock_svc:
        mock_svc.return_value.get_policies.return_value = MOCK_POLICIES
        resp = client.get("/api/v1/sla-policies", params={"org_id": "acme-org"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["policies"]) == 4


# ── PUT /api/v1/sla-policies/{severity} ──────────────────────────────────────

def test_update_policy_success():
    _, client = _make_app()
    updated = {**MOCK_POLICIES[0], "deadline_days": 5}
    with _with_permission(True), patch("src.sla.router.get_sla_service") as mock_svc:
        mock_svc.return_value.update_policy.return_value = updated
        resp = client.put(
            "/api/v1/sla-policies/critical",
            params={"org_id": "acme-org"},
            json={"deadline_days": 5, "enabled": True},
        )
    assert resp.status_code == 200
    assert resp.json()["policy"]["deadline_days"] == 5


def test_update_policy_invalid_severity_returns_400():
    _, client = _make_app()
    with _with_permission(True):
        resp = client.put(
            "/api/v1/sla-policies/unknown",
            params={"org_id": "acme-org"},
            json={"deadline_days": 7, "enabled": True},
        )
    assert resp.status_code == 400


def test_update_policy_zero_deadline_returns_422():
    _, client = _make_app()
    with _with_permission(True):
        resp = client.put(
            "/api/v1/sla-policies/critical",
            params={"org_id": "acme-org"},
            json={"deadline_days": 0, "enabled": True},
        )
    assert resp.status_code == 422


def test_update_policy_no_permission_forbidden():
    _, client = _make_app()
    with _with_permission(False):
        resp = client.put(
            "/api/v1/sla-policies/critical",
            params={"org_id": "acme-org"},
            json={"deadline_days": 7, "enabled": True},
        )
    assert resp.status_code == 403


# ── GET /api/v1/sla/breach-summary ───────────────────────────────────────────

def test_breach_summary_returns_all_severities():
    _, client = _make_app()
    with patch("src.sla.router.get_sla_service") as mock_svc:
        mock_svc.return_value.get_breach_summary.return_value = MOCK_SUMMARY
        resp = client.get("/api/v1/sla/breach-summary", params={"org_id": "acme-org"})
    assert resp.status_code == 200
    summary = resp.json()["summary"]
    assert set(summary.keys()) == {"critical", "high", "medium", "low"}
    assert summary["critical"]["breached"] == 2


# ── POST /api/v1/sla/recompute ───────────────────────────────────────────────

def test_recompute_success():
    _, client = _make_app()
    with _with_permission(True), patch("src.sla.router.get_sla_service") as mock_svc:
        mock_svc.return_value.recompute_org.return_value = 42
        resp = client.post("/api/v1/sla/recompute", params={"org_id": "acme-org"})
    assert resp.status_code == 200
    assert resp.json()["updated"] == 42


def test_recompute_no_permission_forbidden():
    _, client = _make_app()
    with _with_permission(False):
        resp = client.post("/api/v1/sla/recompute", params={"org_id": "acme-org"})
    assert resp.status_code == 403
