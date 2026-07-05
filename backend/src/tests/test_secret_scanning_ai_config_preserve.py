"""Regression tests for the secret_scanning ai-config preservation."""
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


def _patches(existing_config: dict):
    """Stack the patches every test needs.

    - a runner is online (so the prereq gate doesn't trip)
    - read_app_config returns the supplied existing config
    - write_app_config captures what we would have persisted
    """
    captured: dict = {}

    def _capture(cfg, *_args, **_kwargs):
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


def test_save_without_ai_fields_preserves_existing_ai_config():
    """The form never sends aiApiKey/aiReviewEnabled — they must stay put."""
    existing = {
        "tools": {
            "secret_scanning": {
                "enabled": True,
                "aiApiKey": "sk-original-key",
                "aiReviewEnabled": True,
            }
        }
    }
    captured, patches = _patches(existing)
    with patches[0], patches[1], patches[2], patches[3]:
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/settings/tools/secret_scanning",
            json={
                "enabled": True,
                "settings": {
                    "scanConcurrency": "4",
                    "autoRerunEnabled": "false",
                    "rerunScheduleType": "simple",
                    "rerunScheduleValue": "02:00",
                },
            },
        )
        assert resp.status_code == 200, resp.text
    secret_cfg = captured["config"]["tools"]["secret_scanning"]
    assert secret_cfg["aiApiKey"] == "sk-original-key"
    assert secret_cfg["aiReviewEnabled"] is True


def test_save_with_explicit_ai_fields_still_updates_them():
    """When the client opts in, the new values must land."""
    existing = {
        "tools": {
            "secret_scanning": {
                "enabled": True,
                "aiApiKey": "sk-old",
                "aiReviewEnabled": False,
            }
        }
    }
    captured, patches = _patches(existing)
    with patches[0], patches[1], patches[2], patches[3]:
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/settings/tools/secret_scanning",
            json={
                "enabled": True,
                "settings": {
                    "aiApiKey": "sk-new",
                    "aiReviewEnabled": "true",
                    "scanConcurrency": "4",
                },
            },
        )
        assert resp.status_code == 200, resp.text
    secret_cfg = captured["config"]["tools"]["secret_scanning"]
    assert secret_cfg["aiApiKey"] == "sk-new"
    assert secret_cfg["aiReviewEnabled"] is True


def test_redacted_ai_key_preserves_existing_value():
    """The UI sends "[redacted]" for a key it never read — keep the stored one."""
    existing = {
        "tools": {
            "secret_scanning": {
                "enabled": True,
                "aiApiKey": "sk-stored",
                "aiReviewEnabled": True,
            }
        }
    }
    captured, patches = _patches(existing)
    with patches[0], patches[1], patches[2], patches[3]:
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/settings/tools/secret_scanning",
            json={
                "enabled": True,
                "settings": {
                    "aiApiKey": "[redacted]",
                    "aiReviewEnabled": "true",
                    "scanConcurrency": "4",
                },
            },
        )
        assert resp.status_code == 200, resp.text
    secret_cfg = captured["config"]["tools"]["secret_scanning"]
    assert secret_cfg["aiApiKey"] == "sk-stored"
