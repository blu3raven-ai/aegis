"""Regression tests: PATCH /tools/{tool} must preserve fields the client omits."""
from __future__ import annotations

from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.settings.general.router import router as settings_router

_MANAGE_PERMS = {"manage_settings"}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(settings_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
    return app


def _stub_patches(existing_config: dict):
    """Stack the patches every test needs.

    - a fresh runner is online so the prereq gate passes
    - read_app_config returns the supplied existing config
    - write_app_config captures the resulting config
    """
    captured: dict = {}

    def _capture(cfg, *_a, **_kw):
        captured["config"] = cfg

    from datetime import datetime, timezone
    fresh = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    return captured, [
        patch(
            "src.runner.registry.list_approved_online_runners",
            return_value=[{"name": "runner-1", "lastSeen": fresh}],
        ),
        patch("src.settings.general.router.read_app_config", return_value=existing_config),
        patch("src.settings.general.router.write_app_config", side_effect=_capture),
        patch("src.settings.general.router.sync_runtime_env_from_config"),
    ]


def test_iac_save_with_empty_settings_preserves_existing_rerun_config():
    """The IaC form sends settings: {}; existing schedule + auto-rerun must survive."""
    existing = {
        "tools": {
            "iac_scanning": {
                "enabled": False,
                "autoRerunEnabled": True,
                "rerunScheduleType": "cron",
                "rerunScheduleValue": "0 2 * * *",
            }
        }
    }
    captured, patches = _stub_patches(existing)
    with patches[0], patches[1], patches[2], patches[3]:
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/settings/tools/iac_scanning",
            json={"enabled": True, "settings": {}},
        )
        assert resp.status_code == 200, resp.text
    iac_cfg = captured["config"]["tools"]["iac_scanning"]
    assert iac_cfg["enabled"] is True
    assert iac_cfg["autoRerunEnabled"] is True
    assert iac_cfg["rerunScheduleType"] == "cron"
    assert iac_cfg["rerunScheduleValue"] == "0 2 * * *"


def test_dependencies_save_only_updates_keys_in_body():
    """A partial update must leave the other keys alone."""
    existing = {
        "tools": {
            "dependencies_scanning": {
                "enabled": True,
                "scanConcurrency": "8",
                "autoRerunEnabled": True,
                "rerunScheduleType": "cron",
                "rerunScheduleValue": "0 3 * * *",
            }
        }
    }
    captured, patches = _stub_patches(existing)
    with patches[0], patches[1], patches[2], patches[3]:
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/settings/tools/dependencies_scanning",
            json={
                "enabled": True,
                "settings": {"scanConcurrency": "16"},
            },
        )
        assert resp.status_code == 200, resp.text
    deps = captured["config"]["tools"]["dependencies_scanning"]
    assert deps["scanConcurrency"] == "16"
    assert deps["autoRerunEnabled"] is True
    assert deps["rerunScheduleType"] == "cron"
    assert deps["rerunScheduleValue"] == "0 3 * * *"


def test_explicit_value_in_body_still_lands():
    """When the client sends the key, the new value persists."""
    existing = {
        "tools": {
            "dependencies_scanning": {
                "enabled": True,
                "scanConcurrency": "4",
                "autoRerunEnabled": False,
                "rerunScheduleType": "simple",
                "rerunScheduleValue": "02:00",
            }
        }
    }
    captured, patches = _stub_patches(existing)
    with patches[0], patches[1], patches[2], patches[3]:
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/settings/tools/dependencies_scanning",
            json={
                "enabled": True,
                "settings": {
                    "scanConcurrency": "12",
                    "autoRerunEnabled": "false",
                    "rerunScheduleType": "cron",
                    "rerunScheduleValue": "30 4 * * *",
                },
            },
        )
        assert resp.status_code == 200, resp.text
    deps = captured["config"]["tools"]["dependencies_scanning"]
    assert deps["scanConcurrency"] == "12"
    assert deps["autoRerunEnabled"] is False
    assert deps["rerunScheduleType"] == "cron"
    assert deps["rerunScheduleValue"] == "30 4 * * *"
