"""Tests for the auto-dismiss kill switch.

Combines the lightweight router-test pattern (mocked permissions) with the
real-DB store so the SQL filter on (org_id, category) is actually exercised
plus the unique constraint behaviour on duplicate engage.
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import delete

from src.db.helpers import run_db
from src.db.models import RuleKillSwitch
from src.rules.auto_dismiss_matcher import is_kill_switch_active
from src.rules.router import router as rules_router


_ORG_A = "acme-kill-org-a"
_ORG_B = "acme-kill-org-b"


# ── Cleanup ───────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_tables():
    async def _del(session):
        await session.execute(
            delete(RuleKillSwitch).where(RuleKillSwitch.org_id.in_([_ORG_A, _ORG_B]))
        )

    run_db(_del)
    yield
    run_db(_del)


# ── App + permission patching ────────────────────────────────────────────────


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


def _check_active(org_id: str) -> bool:
    async def _q(session):
        return await is_kill_switch_active(
            session, org_id=org_id, category="auto_dismiss"
        )

    return run_db(_q)


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_kill_switch_blocks_auto_dismiss_for_org():
    _, client = _make_app()
    with _with_permission(True):
        resp = client.post(
            "/api/v1/rules/kill-switch/auto_dismiss",
            params={"org_id": _ORG_A},
            json={"reason": "emergency stop"},
        )
    assert resp.status_code == 201

    assert _check_active(_ORG_A) is True


def test_kill_switch_does_not_affect_other_orgs():
    _, client = _make_app()
    with _with_permission(True):
        resp = client.post(
            "/api/v1/rules/kill-switch/auto_dismiss",
            params={"org_id": _ORG_A},
            json={"reason": None},
        )
    assert resp.status_code == 201

    assert _check_active(_ORG_A) is True
    assert _check_active(_ORG_B) is False


def test_kill_switch_removal_re_enables():
    _, client = _make_app()
    with _with_permission(True):
        client.post(
            "/api/v1/rules/kill-switch/auto_dismiss",
            params={"org_id": _ORG_A},
            json={"reason": None},
        )
    assert _check_active(_ORG_A) is True

    with _with_permission(True):
        resp = client.delete(
            "/api/v1/rules/kill-switch/auto_dismiss",
            params={"org_id": _ORG_A},
        )
    assert resp.status_code == 204

    assert _check_active(_ORG_A) is False


def test_kill_switch_requires_permission():
    _, client = _make_app()
    with _with_permission(False):
        resp = client.post(
            "/api/v1/rules/kill-switch/auto_dismiss",
            params={"org_id": _ORG_A},
            json={"reason": None},
        )
    assert resp.status_code == 403


def test_kill_switch_returns_409_on_duplicate_engage():
    _, client = _make_app()
    with _with_permission(True):
        first = client.post(
            "/api/v1/rules/kill-switch/auto_dismiss",
            params={"org_id": _ORG_A},
            json={"reason": "first"},
        )
        second = client.post(
            "/api/v1/rules/kill-switch/auto_dismiss",
            params={"org_id": _ORG_A},
            json={"reason": "second"},
        )

    assert first.status_code == 201
    assert second.status_code == 409
