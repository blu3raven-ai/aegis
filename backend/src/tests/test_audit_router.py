"""Tests for GET /api/v1/settings/audit/events.

Covers permission denial, env-gate, ISO-timestamp validation, limit/offset
clamping, total-count plumbing, and the field remap (``actor_user_id`` →
``actor_id``, ``metadata_json`` → ``metadata``) the previous GQL migration
introduced to fix a long-standing REST contract drift.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import MANAGE_SETTINGS  # noqa: E402
from src.audit_log.router import MAX_LIMIT, router as audit_router  # noqa: E402

_ADMIN_PERMS = {"manage_settings"}
_NO_PERMS: set[str] = set()


def _make_app(*, allow_manage_settings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(audit_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "admin-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_manage_settings:
        app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
    return app


class _SessionCtx:
    """Async context manager wrapping a session mock with a scripted execute."""

    def __init__(self, rows: list, total: int):
        self.session = MagicMock()
        list_result = MagicMock()
        list_result.scalars.return_value.all.return_value = rows
        count_result = MagicMock()
        count_result.scalar_one.return_value = total
        self.session.execute = AsyncMock(side_effect=[list_result, count_result])

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *args):
        return None


def _row(
    *,
    id_: int = 1,
    action: str = "config.updated",
    actor_user_id: str | None = "user-1",
    actor_email: str | None = "alice@example.com",
    actor_role: str | None = "admin",
    resource_type: str | None = "setting",
    resource_id: str | None = "retention",
    request_method: str | None = "POST",
    request_path: str | None = "/api/v1/settings/retention",
    request_ip: str | None = "127.0.0.1",
    user_agent: str | None = "pytest",
    changes: dict | None = None,
    metadata_json: dict | None = None,
    status_code: int | None = 200,
    occurred_at: datetime | None | object = ...,
):
    row = MagicMock()
    row.id = id_
    row.action = action
    row.actor_user_id = actor_user_id
    row.actor_email = actor_email
    row.actor_role = actor_role
    row.resource_type = resource_type
    row.resource_id = resource_id
    row.request_method = request_method
    row.request_path = request_path
    row.request_ip = request_ip
    row.user_agent = user_agent
    row.changes = changes
    row.metadata_json = metadata_json
    row.status_code = status_code
    row.occurred_at = (
        datetime(2026, 1, 1, tzinfo=timezone.utc) if occurred_at is ... else occurred_at
    )
    return row


def _grant():
    return patch(
        "src.authz.enforcement._resolve_effective_permissions",
        return_value=_ADMIN_PERMS,
    )


def _session(rows, total):
    return patch(
        "src.audit_log.router.get_session",
        return_value=_SessionCtx(rows, total),
    )


class _FacetSessionCtx:
    """Session mock scripting the two distinct-column reads the facets route makes."""

    def __init__(self, actions: list[str], resource_types: list[str]):
        self.session = MagicMock()
        actions_result = MagicMock()
        actions_result.scalars.return_value.all.return_value = actions
        resources_result = MagicMock()
        resources_result.scalars.return_value.all.return_value = resource_types
        self.session.execute = AsyncMock(side_effect=[actions_result, resources_result])

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *args):
        return None


def _facet_session(actions, resource_types):
    return patch(
        "src.audit_log.router.get_session",
        return_value=_FacetSessionCtx(actions, resource_types),
    )


# ── permission + env-gate ──────────────────────────────────────────────────


def test_rejects_caller_without_manage_settings_with_403():
    with patch(
        "src.authz.enforcement.dependencies.has_role_permission",
        return_value=False,
    ):
        client = TestClient(_make_app(allow_manage_settings=False))
        resp = client.get("/api/v1/settings/audit/events")

    assert resp.status_code == 403


def test_returns_409_when_env_disables_audit_log(monkeypatch):
    monkeypatch.setenv("AEGIS_AUDIT_LOG_ENABLED", "false")
    with _grant():
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/audit/events")

    assert resp.status_code == 409
    assert "disabled" in resp.json()["detail"].lower()


def test_facets_returns_distinct_actions_and_resource_types():
    with _grant(), _facet_session(["a.created", "b.updated"], ["profile", "scim"]):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/audit/facets")

    assert resp.status_code == 200
    body = resp.json()
    assert body["actions"] == ["a.created", "b.updated"]
    assert body["resource_types"] == ["profile", "scim"]


def test_facets_returns_409_when_env_disables_audit_log(monkeypatch):
    monkeypatch.setenv("AEGIS_AUDIT_LOG_ENABLED", "false")
    with _grant():
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/audit/facets")

    assert resp.status_code == 409


def test_facets_rejects_caller_without_manage_settings_with_403():
    with patch(
        "src.authz.enforcement.dependencies.has_role_permission",
        return_value=False,
    ):
        client = TestClient(_make_app(allow_manage_settings=False))
        resp = client.get("/api/v1/settings/audit/facets")

    assert resp.status_code == 403


# ── filter pass-through + clamping ─────────────────────────────────────────


@pytest.mark.parametrize(
    "raw_limit,expected",
    [(9999, MAX_LIMIT), (-5, 1), (0, 1)],
)
def test_clamps_limit_to_valid_range(raw_limit, expected):
    with _grant(), _session(rows=[], total=0):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/settings/audit/events?limit={raw_limit}")

    assert resp.status_code == 200
    assert resp.json()["limit"] == expected


def test_clamps_negative_offset_to_zero():
    with _grant(), _session(rows=[], total=0):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/audit/events?offset=-10")

    assert resp.status_code == 200
    assert resp.json()["offset"] == 0


def test_invalid_since_returns_400():
    with _grant(), _session(rows=[], total=0):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/audit/events?since=not-an-iso-string")

    assert resp.status_code == 400
    assert "since" in resp.json()["detail"]


def test_invalid_until_returns_400():
    with _grant(), _session(rows=[], total=0):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/audit/events?until=garbage")

    assert resp.status_code == 400
    assert "until" in resp.json()["detail"]


# ── shape correctness — including the field remap ──────────────────────────


def test_remaps_db_field_names_to_public_contract():
    """``actor_user_id`` → ``actor_id`` and ``metadata_json`` → ``metadata``
    is the original contract fix. Verify the wire shape directly."""
    row = _row(
        actor_user_id="user-xyz",
        metadata_json={"foo": "bar"},
        changes={"before": 1, "after": 2},
    )
    with _grant(), _session(rows=[row], total=1):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/audit/events")

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["events"]) == 1
    evt = body["events"][0]
    assert evt["actor_id"] == "user-xyz"
    assert evt["metadata"] == {"foo": "bar"}
    assert evt["changes"] == {"before": 1, "after": 2}
    assert isinstance(evt["occurred_at"], str)
    assert evt["occurred_at"].startswith("2026-01-01")
    assert "actor_user_id" not in evt
    assert "metadata_json" not in evt


def test_returns_total_count_independent_of_page_size():
    rows = [_row(id_=1), _row(id_=2), _row(id_=3)]
    with _grant(), _session(rows=rows, total=42):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/audit/events?limit=3&offset=0")

    body = resp.json()
    assert body["total_count"] == 42
    assert body["limit"] == 3
    assert body["offset"] == 0
    assert len(body["events"]) == 3


def test_q_applies_case_insensitive_substring_filter_across_fields():
    """The `q` search scans action/actor/resource columns with a case-
    insensitive LIKE so one search box replaces the per-facet dropdowns."""
    with _grant(), _session(rows=[_row()], total=1) as get_session_mock:
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/audit/events", params={"q": "Scim"})

    assert resp.status_code == 200
    list_stmt = get_session_mock.return_value.session.execute.call_args_list[0].args[0]
    sql = str(list_stmt.compile(compile_kwargs={"literal_binds": True})).lower()
    assert "like" in sql
    for column in ("action", "actor_email", "actor_role", "resource_type", "resource_id"):
        assert column in sql, column
    # Escaped literal substring, matched case-insensitively.
    assert "%scim%" in sql


def test_q_escapes_like_wildcards_to_match_literally():
    with _grant(), _session(rows=[], total=0) as get_session_mock:
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/audit/events", params={"q": "50%_off"})

    assert resp.status_code == 200
    list_stmt = get_session_mock.return_value.session.execute.call_args_list[0].args[0]
    sql = str(list_stmt.compile(compile_kwargs={"literal_binds": True})).lower()
    assert "50\\%\\_off" in sql


def test_handles_null_occurred_at():
    row = _row(occurred_at=None)
    with _grant(), _session(rows=[row], total=1):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/audit/events")

    assert resp.status_code == 200
    assert resp.json()["events"][0]["occurred_at"] is None
