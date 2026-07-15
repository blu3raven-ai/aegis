"""Audit emission tests for source connection mutations.

Source connections store credentials (PATs, registry passwords, etc.), so
each mutation has to leave a compliance trail. The @audited decorator is
applied at the router; these tests pin the action name, resource_type,
and resource_id captured from the path.
"""
from __future__ import annotations

from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SOURCES
from src.sources.source_connections_router import source_connections_router


_MANAGE_PERMS = {"manage_sources"}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(source_connections_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    app.dependency_overrides[Permission(MANAGE_SOURCES)] = lambda: None
    return app


class _FakeRecorder:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def record(self, *, action, resource_type, resource_id=None, actor=None,
               request=None, metadata=None, **_):
        self.calls.append({
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "actor_user_id": getattr(actor, "user_id", None),
        })


def test_create_connection_records_source_connection_created():
    rec = _FakeRecorder()
    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_MANAGE_PERMS), \
         patch("src.audit_log.recorder.get_recorder", return_value=rec), \
         patch("src.license.limits.check_limit"), \
         patch("src.sources.source_connections_router.sources_store.list_connections",
               return_value=[]), \
         patch("src.sources.source_connections_router.sources_store.create_connection",
               return_value={"id": "conn-new"}):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/sources/connections", json={
            "category": "code-repositories",
            "sourceType": "github",
            "name": "acme",
            "auth": {"orgOrOwner": "acme-org", "token": "tok"},
        })

    assert resp.status_code == 201
    assert len(rec.calls) == 1
    assert rec.calls[0]["action"] == "source_connection.created"
    assert rec.calls[0]["resource_type"] == "source_connection"
    assert rec.calls[0]["actor_user_id"] == "user-1"


def test_update_connection_records_resource_id_from_path():
    rec = _FakeRecorder()
    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_MANAGE_PERMS), \
         patch("src.audit_log.recorder.get_recorder", return_value=rec), \
         patch("src.sources.source_connections_router.sources_store.update_connection",
               return_value={"id": "conn-1"}):
        client = TestClient(_make_app())
        resp = client.put("/api/v1/sources/connections/conn-1",
                          json={"name": "renamed"})

    assert resp.status_code == 200
    assert len(rec.calls) == 1
    assert rec.calls[0]["action"] == "source_connection.updated"
    assert rec.calls[0]["resource_id"] == "conn-1"


def test_delete_connection_records_source_connection_deleted():
    rec = _FakeRecorder()
    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_MANAGE_PERMS), \
         patch("src.audit_log.recorder.get_recorder", return_value=rec), \
         patch("src.sources.source_connections_router.sources_store.delete_connection"):
        client = TestClient(_make_app())
        resp = client.delete("/api/v1/sources/connections/conn-1")

    assert resp.status_code == 200
    assert len(rec.calls) == 1
    assert rec.calls[0]["action"] == "source_connection.deleted"
    assert rec.calls[0]["resource_id"] == "conn-1"


def test_sync_connection_records_source_connection_synced():
    """Manual sync is a privileged action (uses the stored credentials and may
    discover new repos) — must leave a trail."""
    from src.sources.test_connection import ConnectionTestResult

    rec = _FakeRecorder()
    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_MANAGE_PERMS), \
         patch("src.audit_log.recorder.get_recorder", return_value=rec), \
         patch("src.sources.source_connections_router.sources_store.get_connection_with_secrets",
               return_value={"sourceType": "github", "auth": {}, "syncSchedule": "6h"}), \
         patch("src.sources.source_connections_router.sources_store.update_connection_status",
               return_value={"id": "conn-1"}), \
         patch("src.sources.source_connections_router.test_connection",
               return_value=ConnectionTestResult(
                   success=True, message="OK",
                   discovered_count=3, discovered_items=["a", "b", "c"],
               )):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/sources/connections/conn-1/sync")

    assert resp.status_code == 200
    assert len(rec.calls) == 1
    assert rec.calls[0]["action"] == "source_connection.synced"
    assert rec.calls[0]["resource_id"] == "conn-1"
