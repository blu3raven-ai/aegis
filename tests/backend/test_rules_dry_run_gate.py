"""Tests for the auto-dismiss enable dry-run-and-confirm gate.

The gate enforces that an auto_dismiss rule can only flip from disabled to
enabled when paired with a fresh, single-use confirmation token minted by
``POST /rules/{id}/dry-run-and-confirm``. These tests exercise the full path
through TestClient + the real store so the SQL token persistence is covered.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from src.db.helpers import run_db
from src.db.models import Rule
from src.rules.router import router as rules_router


_ORG = "acme-dry-run-org"


# ── Cleanup ───────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_tables():
    async def _del(session):
        await session.execute(delete(Rule).where(Rule.org_id == _ORG))

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


# ── Seeding helpers ───────────────────────────────────────────────────────────


def _seed_rule(
    *,
    rule_id: str,
    category: str = "auto_dismiss",
    enabled: bool = False,
    action: dict | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    default_action = (
        {"reason": "test", "rate_alarm_pct": 50.0, "rate_alarm_window_minutes": 60}
        if category == "auto_dismiss"
        else {"deadline_days": 7, "escalations": []}
    )

    async def _insert(session):
        session.add(Rule(
            id=rule_id,
            org_id=_ORG,
            category=category,
            name=f"test-{rule_id}",
            description=None,
            enabled=enabled,
            priority=100,
            conditions={"all": []},
            action=action or default_action,
            created_by="usr-test",
            created_at=now,
            updated_at=now,
        ))

    run_db(_insert)
    return rule_id


def _mint_token(rule_id: str) -> str:
    """Call dry-run-and-confirm to mint a token; return it."""
    _, client = _make_app()
    with _with_permission(True):
        resp = client.post(
            f"/api/v1/rules/{rule_id}/dry-run-and-confirm",
            params={"org_id": _ORG},
        )
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _get_rule_row(rule_id: str) -> Rule | None:
    async def _q(session):
        row = (
            await session.execute(select(Rule).where(Rule.id == rule_id))
        ).scalars().first()
        if row is not None:
            session.expunge(row)
        return row

    return run_db(_q)


def _set_last_dry_run_at(rule_id: str, when: datetime) -> None:
    async def _u(session):
        row = (
            await session.execute(select(Rule).where(Rule.id == rule_id))
        ).scalars().first()
        row.last_dry_run_at = when

    run_db(_u)


# ── PUT gate failure paths ───────────────────────────────────────────────────


def test_enable_auto_dismiss_without_token_rejected():
    _seed_rule(rule_id="rule-no-token")
    _, client = _make_app()

    with _with_permission(True):
        resp = client.put(
            "/api/v1/rules/rule-no-token",
            params={"org_id": _ORG},
            json={"enabled": True},
        )

    assert resp.status_code == 400
    assert "token" in resp.json()["detail"].lower()


def test_enable_auto_dismiss_with_expired_token_rejected():
    _seed_rule(rule_id="rule-expired")
    token = _mint_token("rule-expired")

    # Backdate the dry-run timestamp by 2h to push past the 1h TTL.
    two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)
    _set_last_dry_run_at("rule-expired", two_hours_ago)

    _, client = _make_app()
    with _with_permission(True):
        resp = client.put(
            "/api/v1/rules/rule-expired",
            params={"org_id": _ORG},
            json={"enabled": True, "dry_run_confirmation_token": token},
        )

    assert resp.status_code == 400
    assert "expired" in resp.json()["detail"].lower()


def test_enable_auto_dismiss_with_wrong_token_rejected():
    _seed_rule(rule_id="rule-wrong-token")
    _mint_token("rule-wrong-token")

    _, client = _make_app()
    with _with_permission(True):
        resp = client.put(
            "/api/v1/rules/rule-wrong-token",
            params={"org_id": _ORG},
            json={"enabled": True, "dry_run_confirmation_token": "completely-bogus-token"},
        )

    assert resp.status_code == 400
    assert "match" in resp.json()["detail"].lower()


# ── PUT gate happy path ──────────────────────────────────────────────────────


def test_enable_auto_dismiss_with_fresh_token_succeeds():
    _seed_rule(rule_id="rule-fresh")
    token = _mint_token("rule-fresh")

    _, client = _make_app()
    with _with_permission(True):
        resp = client.put(
            "/api/v1/rules/rule-fresh",
            params={"org_id": _ORG},
            json={"enabled": True, "dry_run_confirmation_token": token},
        )

    assert resp.status_code == 200
    assert resp.json()["rule"]["enabled"] is True

    row = _get_rule_row("rule-fresh")
    assert row.enabled is True
    # Token must be cleared as soon as it's consumed.
    assert row.dry_run_confirmation_token is None
    assert row.dry_run_confirmed_at is not None


def test_dry_run_token_single_use():
    """A successful gate consumption clears the token; a follow-up enable with
    the same token must fail because no pending dry-run remains.
    """
    _seed_rule(rule_id="rule-single-use")
    token = _mint_token("rule-single-use")
    _, client = _make_app()

    with _with_permission(True):
        first = client.put(
            "/api/v1/rules/rule-single-use",
            params={"org_id": _ORG},
            json={"enabled": True, "dry_run_confirmation_token": token},
        )
    assert first.status_code == 200

    # Disable so the next enable transition actually fires the gate.
    with _with_permission(True):
        disable = client.put(
            "/api/v1/rules/rule-single-use",
            params={"org_id": _ORG},
            json={"enabled": False},
        )
    assert disable.status_code == 200

    with _with_permission(True):
        replay = client.put(
            "/api/v1/rules/rule-single-use",
            params={"org_id": _ORG},
            json={"enabled": True, "dry_run_confirmation_token": token},
        )
    assert replay.status_code == 400


# ── Other categories skip the gate ───────────────────────────────────────────


def test_other_categories_skip_dry_run_gate():
    _seed_rule(rule_id="sla-no-gate", category="sla", enabled=False)
    _, client = _make_app()

    with _with_permission(True):
        resp = client.put(
            "/api/v1/rules/sla-no-gate",
            params={"org_id": _ORG},
            json={"enabled": True},
        )

    assert resp.status_code == 200
    assert resp.json()["rule"]["enabled"] is True


# ── Create- and toggle-side bypass guards ────────────────────────────────────


def test_create_auto_dismiss_with_enabled_true_rejected():
    _, client = _make_app()
    body = {
        "org_id": _ORG,
        "category": "auto_dismiss",
        "name": "cannot-create-enabled",
        "enabled": True,
        "action": {"reason": "test", "rate_alarm_pct": 50.0, "rate_alarm_window_minutes": 60},
    }
    with _with_permission(True):
        resp = client.post("/api/v1/rules", json=body)

    assert resp.status_code == 400
    detail = resp.json()["detail"].lower()
    assert "disabled" in detail or "dry-run" in detail


def test_toggle_auto_dismiss_disabled_to_enabled_rejected():
    _seed_rule(rule_id="rule-toggle-block", enabled=False)
    _, client = _make_app()

    with _with_permission(True):
        resp = client.post(
            "/api/v1/rules/rule-toggle-block/toggle",
            params={"org_id": _ORG},
        )

    assert resp.status_code == 400
