"""Rules-engine mutations must leave an audit trail.

/api/v1/rules is not covered by the global audit middleware (its prefix isn't in
the middleware allowlist), so each mutating handler records its own event. Rule
changes drive auto-dismiss / auto-archive of findings, so the trail matters for
the compliance story.
"""
from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

import pytest  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.rules.router import router as rules_router  # noqa: E402


def _rule_row(rule_id: str = "sla-abc", category: str = "sla") -> dict:
    return {
        "id": rule_id,
        "category": category,
        "name": "Critical SLA",
        "description": "fix criticals fast",
        "enabled": True,
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


class _CapturingRecorder:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def record(self, **kwargs) -> None:
        self.events.append(kwargs)


@pytest.fixture
def client_and_audit():
    """App wired with an admin identity, the manage gate stubbed open, the rules
    store faked, and the audit recorder captured."""
    rec = _CapturingRecorder()
    app = FastAPI()
    app.include_router(rules_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "admin-1"
        request.state.user_id = "admin-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    with patch("src.rules.router.require_permission", lambda *a, **k: None), \
         patch("src.rules.router.validate_action_for_category", lambda *a, **k: None), \
         patch("src.rules.router.get_recorder", lambda: rec), \
         patch("src.rules.router.store") as store:
        store.create_rule.return_value = _rule_row()
        store.update_rule.return_value = _rule_row()
        store.toggle_rule.return_value = {**_rule_row(), "enabled": False}
        store.delete_rule.return_value = None
        store.get_rule_by_id.return_value = _rule_row()
        store.engage_kill_switch.return_value = {"category": "auto_dismiss", "engaged": True}
        store.disengage_kill_switch.return_value = True
        yield TestClient(app), rec


def _only(rec: _CapturingRecorder) -> dict:
    assert len(rec.events) == 1, f"expected exactly one audit event, got {rec.events}"
    return rec.events[0]


def test_create_rule_audited(client_and_audit):
    client, rec = client_and_audit
    resp = client.post("/api/v1/rules", json={
        "category": "sla", "name": "Critical SLA", "description": "x",
        "enabled": True, "priority": 100,
        "conditions": {"field": "severity", "op": "eq", "value": "critical"},
        "action": {"deadline_days": 7, "escalations": []},
    })
    assert resp.status_code == 201
    ev = _only(rec)
    assert ev["action"] == "rule.created"
    assert ev["resource_type"] == "rule"
    assert ev["resource_id"] == "sla-abc"
    assert ev["actor"].user_id == "admin-1" and ev["actor"].role == "admin"
    assert ev["metadata"]["category"] == "sla"


def test_toggle_rule_audited(client_and_audit):
    client, rec = client_and_audit
    resp = client.post("/api/v1/rules/sla-abc/toggle")
    assert resp.status_code == 200
    ev = _only(rec)
    assert ev["action"] == "rule.toggled"
    assert ev["resource_id"] == "sla-abc"
    assert ev["metadata"]["enabled"] is False


def test_update_rule_audited(client_and_audit):
    client, rec = client_and_audit
    resp = client.put("/api/v1/rules/sla-abc", json={"priority": 50})
    assert resp.status_code == 200
    ev = _only(rec)
    assert ev["action"] == "rule.updated"
    assert ev["resource_id"] == "sla-abc"
    assert "priority" in ev["metadata"]["fields"]


def test_delete_rule_audited(client_and_audit):
    client, rec = client_and_audit
    resp = client.delete("/api/v1/rules/sla-abc")
    assert resp.status_code == 204
    ev = _only(rec)
    assert ev["action"] == "rule.deleted"
    assert ev["resource_id"] == "sla-abc"


def test_kill_switch_engage_and_disengage_audited(client_and_audit):
    client, rec = client_and_audit
    resp = client.post("/api/v1/rules/kill-switch/auto_dismiss", json={"reason": "incident"})
    assert resp.status_code == 201
    ev = _only(rec)
    assert ev["action"] == "rule.kill_switch.engaged"
    assert ev["resource_type"] == "rule_kill_switch"
    assert ev["resource_id"] == "auto_dismiss"
    assert ev["metadata"]["reason"] == "incident"

    rec.events.clear()
    resp = client.delete("/api/v1/rules/kill-switch/auto_dismiss")
    assert resp.status_code == 204
    ev = _only(rec)
    assert ev["action"] == "rule.kill_switch.disengaged"
    assert ev["resource_id"] == "auto_dismiss"
