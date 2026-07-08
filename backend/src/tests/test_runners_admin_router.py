"""Tests for the runner admin REST endpoints.

Covers all 6 mutations migrated from GQL:
  POST /api/v1/runners/tokens
  PATCH /api/v1/runners/{runner_id}/settings
  POST /api/v1/runners/{runner_id}/approve
  POST /api/v1/runners/{runner_id}/revoke
  DELETE /api/v1/runners/{runner_id}
  POST /api/v1/runners/{runner_id}/rotate-token
"""
from __future__ import annotations

import os
from unittest.mock import patch

from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import MANAGE_RUNNERS  # noqa: E402
from src.runner.admin_router import router as runners_admin_router  # noqa: E402

_MANAGE_PERMS = {"manage_runners"}
_NO_PERMS: set[str] = set()

_RUNNER_ID = "runner-abc123"
_NOW = "2026-01-01T00:00:00+00:00"

_FAKE_RUNNER_DICT = {
    "id": _RUNNER_ID,
    "name": "test-runner",
    "status": "online",
    "os": "linux",
    "arch": "amd64",
    "registeredAt": _NOW,
    "approvedAt": _NOW,
    "lastHeartbeatAt": _NOW,
    "jobsCompleted": 5,
    "maxConcurrent": 2,
    "cpuPercent": 12.5,
    "cores": 4,
    "healthPercent": 90,
}


def _make_app(*, allow_manage_runners: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(runners_admin_router)

    @app.middleware("http")
    async def inject_state(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        request.state.tier = "enterprise"
        return await call_next(request)

    if allow_manage_runners:
        # Declarative Depends(Permission(MANAGE_RUNNERS)) hits has_role_permission
        # → run_db, which has no DB in unit tests. Override for happy paths;
        # the 403 tests use allow_manage_runners=False and patch
        # has_role_permission directly to exercise the real gate.
        app.dependency_overrides[Permission(MANAGE_RUNNERS)] = lambda: None
    return app


# ---------------------------------------------------------------------------
# POST /api/v1/runners/tokens — generate registration token
# ---------------------------------------------------------------------------

def test_generate_token_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        client = TestClient(_make_app(allow_manage_runners=False))
        resp = client.post("/api/v1/runners/tokens")
        assert resp.status_code == 403


def test_generate_token_happy_path():
    fake_result = {"token": "raw-token-xyz", "expiresAt": _NOW}

    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.generate_token", return_value=fake_result):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/runners/tokens")
        assert resp.status_code == 200
        body = resp.json()
        assert body["token"] == "raw-token-xyz"
        assert body["expiresAt"] == _NOW


# ---------------------------------------------------------------------------
# PATCH /api/v1/runners/{runner_id}/settings — update runner settings
# ---------------------------------------------------------------------------

def test_update_settings_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        client = TestClient(_make_app(allow_manage_runners=False))
        resp = client.patch(f"/api/v1/runners/{_RUNNER_ID}/settings", json={"maxConcurrent": 4})
        assert resp.status_code == 403


def test_update_settings_happy_path():
    fake_runner = {**_FAKE_RUNNER_DICT, "maxConcurrent": 4}

    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.update_settings", return_value=fake_runner):
        client = TestClient(_make_app())
        resp = client.patch(f"/api/v1/runners/{_RUNNER_ID}/settings", json={"maxConcurrent": 4})
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == _RUNNER_ID
        assert body["maxConcurrent"] == 4


def test_update_settings_422_no_fields():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.update_settings",
               side_effect=HTTPException(status_code=422, detail="No settings provided")):
        client = TestClient(_make_app())
        resp = client.patch(f"/api/v1/runners/{_RUNNER_ID}/settings", json={})
        assert resp.status_code == 422


def test_update_settings_404_not_found():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.update_settings",
               side_effect=HTTPException(status_code=404, detail="Runner not found")):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/runners/nonexistent/settings", json={"name": "x"})
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/v1/runners/{runner_id}/approve
# ---------------------------------------------------------------------------

def test_approve_runner_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        client = TestClient(_make_app(allow_manage_runners=False))
        resp = client.post(f"/api/v1/runners/{_RUNNER_ID}/approve")
        assert resp.status_code == 403


def test_approve_runner_happy_path():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.approve", return_value={"ok": True}):
        client = TestClient(_make_app())
        resp = client.post(f"/api/v1/runners/{_RUNNER_ID}/approve")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}


def test_approve_runner_rejected_at_license_limit():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.approve",
               side_effect=HTTPException(status_code=403, detail="plan limit")):
        client = TestClient(_make_app())
        resp = client.post(f"/api/v1/runners/{_RUNNER_ID}/approve")
        assert resp.status_code == 403


def test_approve_runner_404_not_found():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.approve",
               side_effect=HTTPException(status_code=404, detail="Runner not found")):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/runners/nonexistent/approve")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/v1/runners/{runner_id}/revoke
# ---------------------------------------------------------------------------

def test_revoke_runner_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        client = TestClient(_make_app(allow_manage_runners=False))
        resp = client.post(f"/api/v1/runners/{_RUNNER_ID}/revoke")
        assert resp.status_code == 403


def test_revoke_runner_happy_path():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.revoke", return_value={"ok": True}):
        client = TestClient(_make_app())
        resp = client.post(f"/api/v1/runners/{_RUNNER_ID}/revoke")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}


def test_revoke_runner_404_not_found():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.revoke",
               side_effect=HTTPException(status_code=404, detail="Runner not found")):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/runners/nonexistent/revoke")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /api/v1/runners/{runner_id}
# ---------------------------------------------------------------------------

def test_delete_runner_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        client = TestClient(_make_app(allow_manage_runners=False))
        resp = client.delete(f"/api/v1/runners/{_RUNNER_ID}")
        assert resp.status_code == 403


def test_delete_runner_happy_path():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.remove", return_value={"ok": True}):
        client = TestClient(_make_app())
        resp = client.delete(f"/api/v1/runners/{_RUNNER_ID}")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}


def test_delete_runner_404_not_found():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.remove",
               side_effect=HTTPException(status_code=404, detail="Runner not found")):
        client = TestClient(_make_app())
        resp = client.delete("/api/v1/runners/nonexistent")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/v1/runners/{runner_id}/rotate-token
# ---------------------------------------------------------------------------

def test_rotate_token_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        client = TestClient(_make_app(allow_manage_runners=False))
        resp = client.post(f"/api/v1/runners/{_RUNNER_ID}/rotate-token")
        assert resp.status_code == 403


def test_rotate_token_happy_path():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.rotate_token",
               return_value={"ok": True, "newToken": "new-tok-abc"}):
        client = TestClient(_make_app())
        resp = client.post(f"/api/v1/runners/{_RUNNER_ID}/rotate-token")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["newToken"] == "new-tok-abc"


def test_rotate_token_404_not_found():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.rotate_token",
               side_effect=HTTPException(status_code=404, detail="Runner not found")):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/runners/nonexistent/rotate-token")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# CSRF — real main.app TestClient exercises CSRFMiddleware
# ---------------------------------------------------------------------------

def test_csrf_rejects_post_without_token():
    """CSRFMiddleware must block state-changing requests without a CSRF token."""
    from src.main import app

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post(
        "/api/v1/runners/tokens",
        cookies={},
        headers={},
    )
    assert resp.status_code in (403, 401)


# ---------------------------------------------------------------------------
# Response shape — camelCase field names
# ---------------------------------------------------------------------------

def test_update_settings_response_is_camel_case():
    fake_runner = {**_FAKE_RUNNER_DICT, "name": "my-runner"}

    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.runner.admin_router.update_settings", return_value=fake_runner):
        client = TestClient(_make_app())
        resp = client.patch(f"/api/v1/runners/{_RUNNER_ID}/settings", json={"name": "my-runner"})
        assert resp.status_code == 200
        body = resp.json()
        # camelCase keys expected
        assert "registeredAt" in body
        assert "approvedAt" in body
        assert "lastHeartbeatAt" in body
        assert "jobsCompleted" in body
        assert "maxConcurrent" in body
        assert "healthPercent" in body
        # snake_case must NOT appear
        assert "registered_at" not in body
        assert "approved_at" not in body


# ---------------------------------------------------------------------------
# Audit log emissions — every privileged mutation must leave a trail
# ---------------------------------------------------------------------------

class _FakeRecorder:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def record(self, *, action: str, resource_type: str, resource_id=None,
               actor=None, request=None, metadata=None, **_):
        self.calls.append({
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "actor_user_id": getattr(actor, "user_id", None),
            "metadata": metadata or {},
        })


def _run_with_audit_capture(action_kwargs, runner_id_in_path: bool = True):
    """Invoke one endpoint and return (audit_calls, response).

    `action_kwargs` is a dict of: {method, path, json (optional), patch_target,
    patch_return}.
    """
    rec = _FakeRecorder()
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_PERMS), \
         patch("src.audit_log.recorder.get_recorder", return_value=rec), \
         patch(action_kwargs["patch_target"], return_value=action_kwargs["patch_return"]):
        client = TestClient(_make_app())
        method = action_kwargs["method"].lower()
        if "json" in action_kwargs:
            resp = getattr(client, method)(action_kwargs["path"], json=action_kwargs["json"])
        else:
            resp = getattr(client, method)(action_kwargs["path"])
    return rec.calls, resp


def test_audit_generate_token_fires_runner_token_generated():
    calls, resp = _run_with_audit_capture({
        "method": "POST", "path": "/api/v1/runners/tokens",
        "patch_target": "src.runner.admin_router.generate_token",
        "patch_return": {"token": "raw-token-xyz", "expiresAt": _NOW},
    })
    assert resp.status_code == 200
    assert len(calls) == 1
    assert calls[0]["action"] == "runner.token.generated"
    assert calls[0]["resource_type"] == "runner_registration_token"
    assert calls[0]["actor_user_id"] == "user-1"


def test_audit_approve_records_runner_id_as_resource():
    calls, resp = _run_with_audit_capture({
        "method": "POST", "path": f"/api/v1/runners/{_RUNNER_ID}/approve",
        "patch_target": "src.runner.admin_router.approve",
        "patch_return": _FAKE_RUNNER_DICT,
    })
    assert resp.status_code == 200
    assert len(calls) == 1
    assert calls[0]["action"] == "runner.approved"
    assert calls[0]["resource_type"] == "runner"
    assert calls[0]["resource_id"] == _RUNNER_ID


def test_audit_revoke_records_runner_id_as_resource():
    calls, resp = _run_with_audit_capture({
        "method": "POST", "path": f"/api/v1/runners/{_RUNNER_ID}/revoke",
        "patch_target": "src.runner.admin_router.revoke",
        "patch_return": {"ok": True},
    })
    assert resp.status_code == 200
    assert calls[0]["action"] == "runner.revoked"
    assert calls[0]["resource_id"] == _RUNNER_ID


def test_audit_delete_records_runner_id_as_resource():
    calls, resp = _run_with_audit_capture({
        "method": "DELETE", "path": f"/api/v1/runners/{_RUNNER_ID}",
        "patch_target": "src.runner.admin_router.remove",
        "patch_return": {"ok": True},
    })
    assert resp.status_code == 200
    assert calls[0]["action"] == "runner.deleted"
    assert calls[0]["resource_id"] == _RUNNER_ID


def test_audit_rotate_token_records_runner_id_as_resource():
    calls, resp = _run_with_audit_capture({
        "method": "POST", "path": f"/api/v1/runners/{_RUNNER_ID}/rotate-token",
        "patch_target": "src.runner.admin_router.rotate_token",
        "patch_return": {"ok": True, "newToken": "new-raw-tok"},
    })
    assert resp.status_code == 200
    assert calls[0]["action"] == "runner.token.rotated"
    assert calls[0]["resource_id"] == _RUNNER_ID


def test_audit_settings_update_records_runner_id_as_resource():
    calls, resp = _run_with_audit_capture({
        "method": "PATCH", "path": f"/api/v1/runners/{_RUNNER_ID}/settings",
        "json": {"maxConcurrent": 4},
        "patch_target": "src.runner.admin_router.update_settings",
        "patch_return": {**_FAKE_RUNNER_DICT, "maxConcurrent": 4},
    })
    assert resp.status_code == 200
    assert calls[0]["action"] == "runner.settings.updated"
    assert calls[0]["resource_id"] == _RUNNER_ID
