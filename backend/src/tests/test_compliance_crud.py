"""Tests for /api/v1/compliance/frameworks CRUD endpoints."""
from __future__ import annotations

import asyncio
import os
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.compliance.models import Framework, FrameworkControl  # noqa: E402
from src.compliance.router import router as compliance_router  # noqa: E402
from src.compliance.service import (  # noqa: E402
    ControlAlreadyExists,
    ControlNotFound,
    FrameworkAlreadyExists,
    FrameworkNotCustom,
    FrameworkNotFound,
)


_ADMIN_PERMS = {"manage_settings", "view_findings"}
_VIEWER_PERMS = {"view_findings"}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(compliance_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "admin@example.com"
        return await call_next(request)

    return app


def _run_closure(coro_fn):
    """Run the router's async _query closure with a mock session.

    Patches in for run_db so service-helper exceptions raised inside the closure
    propagate to the router's try/except where they're mapped to HTTPException.

    Runs on a dedicated thread + fresh loop because the FastAPI test client is
    already executing on an asyncio loop in this thread, which forbids nested
    asyncio.run().
    """
    result_box: dict = {}
    error_box: dict = {}

    def _worker():
        loop = asyncio.new_event_loop()
        try:
            result_box["value"] = loop.run_until_complete(coro_fn(MagicMock()))
        except BaseException as exc:
            error_box["error"] = exc
        finally:
            loop.close()

    t = threading.Thread(target=_worker)
    t.start()
    t.join()
    if "error" in error_box:
        raise error_box["error"]
    return result_box["value"]


def _fake_framework(framework_id: str = "acme-2026", label: str = "ACME 2026") -> Framework:
    return Framework(
        id=framework_id,
        label=label,
        description=None,
        is_custom=True,
        created_by_user_id="admin@example.com",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def _fake_control(framework_id: str = "acme-2026", control_id: str = "A.1") -> FrameworkControl:
    return FrameworkControl(
        id=1,
        framework=framework_id,
        control_id=control_id,
        title="Access control",
        description=None,
        category=None,
        is_custom=True,
        created_by_user_id="admin@example.com",
        created_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Framework: create
# ---------------------------------------------------------------------------


def test_create_framework():
    app = _make_app()
    recorder = MagicMock()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.run_db", return_value=_fake_framework()),
        patch("src.compliance.router.get_recorder", return_value=recorder),
    ):
        r = TestClient(app).post(
            "/api/v1/compliance/frameworks",
            json={"id": "acme-2026", "label": "ACME 2026"},
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["id"] == "acme-2026"
    assert body["is_custom"] is True
    recorder.record.assert_called_once()
    call = recorder.record.call_args
    assert call.kwargs["action"] == "framework.created"
    assert call.kwargs["resource_type"] == "framework"


def test_create_framework_requires_permission():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS):
        r = TestClient(app).post(
            "/api/v1/compliance/frameworks",
            json={"id": "x", "label": "X"},
        )
    assert r.status_code == 403


def test_create_framework_id_validation_422():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch(
            "src.compliance.router.create_framework",
            side_effect=ValueError("framework id must be lowercase alphanumeric with optional hyphens, max 64 chars"),
        ),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
    ):
        r = TestClient(app).post(
            "/api/v1/compliance/frameworks",
            json={"id": "Invalid Name", "label": "x"},
        )
    assert r.status_code == 422
    assert "framework id must be" in r.json()["detail"]


def test_create_framework_duplicate_returns_409():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch(
            "src.compliance.router.create_framework",
            side_effect=FrameworkAlreadyExists("acme-2026"),
        ),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
    ):
        r = TestClient(app).post(
            "/api/v1/compliance/frameworks",
            json={"id": "acme-2026", "label": "ACME 2026"},
        )
    assert r.status_code == 409
    assert "already exists" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Framework: update
# ---------------------------------------------------------------------------


def test_patch_framework_updates_custom():
    app = _make_app()
    recorder = MagicMock()
    updated = _fake_framework(label="ACME 2026 v2")
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.run_db", return_value=updated),
        patch("src.compliance.router.get_recorder", return_value=recorder),
    ):
        r = TestClient(app).patch(
            "/api/v1/compliance/frameworks/acme-2026",
            json={"label": "ACME 2026 v2"},
        )
    assert r.status_code == 200, r.text
    assert r.json()["label"] == "ACME 2026 v2"
    recorder.record.assert_called_once()
    assert recorder.record.call_args.kwargs["action"] == "framework.updated"


def test_patch_framework_empty_body_returns_422():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        r = TestClient(app).patch(
            "/api/v1/compliance/frameworks/acme-2026",
            json={},
        )
    assert r.status_code == 422


def test_patch_bundled_framework_returns_403():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.update_framework", side_effect=FrameworkNotCustom("soc2")),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
    ):
        r = TestClient(app).patch(
            "/api/v1/compliance/frameworks/soc2",
            json={"label": "New"},
        )
    assert r.status_code == 403


def test_patch_missing_framework_returns_404():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.update_framework", side_effect=FrameworkNotFound("nope")),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
    ):
        r = TestClient(app).patch(
            "/api/v1/compliance/frameworks/nope",
            json={"label": "x"},
        )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Framework: delete
# ---------------------------------------------------------------------------


def test_delete_custom_framework():
    app = _make_app()
    recorder = MagicMock()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.delete_framework", return_value=None),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
        patch("src.compliance.router.get_recorder", return_value=recorder),
    ):
        r = TestClient(app).delete("/api/v1/compliance/frameworks/acme-2026")
    assert r.status_code == 204
    recorder.record.assert_called_once()
    assert recorder.record.call_args.kwargs["action"] == "framework.deleted"


def test_delete_bundled_framework_returns_403():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.delete_framework", side_effect=FrameworkNotCustom("soc2")),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
    ):
        r = TestClient(app).delete("/api/v1/compliance/frameworks/soc2")
    assert r.status_code == 403


def test_delete_missing_framework_returns_404():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.delete_framework", side_effect=FrameworkNotFound("nope")),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
    ):
        r = TestClient(app).delete("/api/v1/compliance/frameworks/nope")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Control: create
# ---------------------------------------------------------------------------


def test_add_control_to_custom_framework():
    app = _make_app()
    recorder = MagicMock()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.run_db", return_value=_fake_control()),
        patch("src.compliance.router.get_recorder", return_value=recorder),
    ):
        r = TestClient(app).post(
            "/api/v1/compliance/frameworks/acme-2026/controls",
            json={"control_id": "A.1", "title": "Access control"},
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["control_id"] == "A.1"
    recorder.record.assert_called_once()
    call = recorder.record.call_args
    assert call.kwargs["action"] == "framework_control.created"
    assert call.kwargs["resource_type"] == "framework_control"
    assert call.kwargs["resource_id"] == "acme-2026:A.1"


def test_add_control_to_bundled_framework_returns_403():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.add_control", side_effect=FrameworkNotCustom("soc2")),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
    ):
        r = TestClient(app).post(
            "/api/v1/compliance/frameworks/soc2/controls",
            json={"control_id": "X.1", "title": "x"},
        )
    assert r.status_code == 403


def test_duplicate_control_returns_409():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.add_control", side_effect=ControlAlreadyExists("A.1")),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
    ):
        r = TestClient(app).post(
            "/api/v1/compliance/frameworks/acme-2026/controls",
            json={"control_id": "A.1", "title": "x"},
        )
    assert r.status_code == 409


def test_add_control_unknown_framework_returns_404():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.add_control", side_effect=FrameworkNotFound("nope")),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
    ):
        r = TestClient(app).post(
            "/api/v1/compliance/frameworks/nope/controls",
            json={"control_id": "A.1", "title": "x"},
        )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Control: update
# ---------------------------------------------------------------------------


def test_patch_control_updates_custom():
    app = _make_app()
    recorder = MagicMock()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.run_db", return_value=_fake_control()),
        patch("src.compliance.router.get_recorder", return_value=recorder),
    ):
        r = TestClient(app).patch(
            "/api/v1/compliance/frameworks/acme-2026/controls/A.1",
            json={"title": "Access control v2"},
        )
    assert r.status_code == 200, r.text
    recorder.record.assert_called_once()
    assert recorder.record.call_args.kwargs["action"] == "framework_control.updated"


def test_patch_control_empty_body_returns_422():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        r = TestClient(app).patch(
            "/api/v1/compliance/frameworks/acme-2026/controls/A.1",
            json={},
        )
    assert r.status_code == 422


def test_patch_control_missing_returns_404():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.update_control", side_effect=ControlNotFound("X.99")),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
    ):
        r = TestClient(app).patch(
            "/api/v1/compliance/frameworks/acme-2026/controls/X.99",
            json={"title": "x"},
        )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Control: delete
# ---------------------------------------------------------------------------


def test_delete_control():
    app = _make_app()
    recorder = MagicMock()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.delete_control", return_value=None),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
        patch("src.compliance.router.get_recorder", return_value=recorder),
    ):
        r = TestClient(app).delete("/api/v1/compliance/frameworks/acme-2026/controls/A.1")
    assert r.status_code == 204
    recorder.record.assert_called_once()
    call = recorder.record.call_args
    assert call.kwargs["action"] == "framework_control.deleted"
    assert call.kwargs["resource_id"] == "acme-2026:A.1"


def test_delete_control_from_bundled_returns_403():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS),
        patch("src.compliance.router.delete_control", side_effect=FrameworkNotCustom("soc2")),
        patch("src.compliance.router.run_db", new=lambda fn: _run_closure(fn)),
    ):
        r = TestClient(app).delete("/api/v1/compliance/frameworks/soc2/controls/CC1.1")
    assert r.status_code == 403


def test_write_endpoints_require_manage_settings():
    """Smoke check: all six write endpoints reject callers without manage_settings."""
    app = _make_app()
    client = TestClient(app)
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS):
        assert client.post(
            "/api/v1/compliance/frameworks",
            json={"id": "x", "label": "x"},
        ).status_code == 403
        assert client.patch(
            "/api/v1/compliance/frameworks/x",
            json={"label": "y"},
        ).status_code == 403
        assert client.delete("/api/v1/compliance/frameworks/x").status_code == 403
        assert client.post(
            "/api/v1/compliance/frameworks/x/controls",
            json={"control_id": "c", "title": "t"},
        ).status_code == 403
        assert client.patch(
            "/api/v1/compliance/frameworks/x/controls/c",
            json={"title": "t"},
        ).status_code == 403
        assert client.delete(
            "/api/v1/compliance/frameworks/x/controls/c"
        ).status_code == 403
