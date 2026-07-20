"""POST /settings/advisory-key/test validates a key against its upstream without persisting."""
from __future__ import annotations

from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.settings.general.router import router as settings_router


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


def test_valid_ghsa_key_returns_valid_true():
    client = TestClient(_make_app())
    with patch(
        "src.settings.general.router._validate_ghsa_api_key",
        return_value=(True, ""),
    ) as mock:
        resp = client.post("/api/v1/settings/advisory-key/test", json={"source": "ghsa", "apiKey": "ghp_good"})
    assert resp.status_code == 200
    assert resp.json() == {"valid": True, "error": ""}
    mock.assert_called_once_with("ghp_good")


def test_invalid_ghsa_key_returns_valid_false_with_reason():
    client = TestClient(_make_app())
    with patch(
        "src.settings.general.router._validate_ghsa_api_key",
        return_value=(False, "GitHub PAT is invalid or has expired."),
    ):
        resp = client.post("/api/v1/settings/advisory-key/test", json={"source": "ghsa", "apiKey": "ghp_bad"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is False
    assert "expired" in body["error"]


def test_nvd_source_routes_to_nvd_validator():
    client = TestClient(_make_app())
    with patch("src.settings.general.router._validate_nvd_api_key", return_value=(True, "")) as nvd, patch(
        "src.settings.general.router._validate_ghsa_api_key"
    ) as ghsa:
        resp = client.post("/api/v1/settings/advisory-key/test", json={"source": "nvd", "apiKey": "nvd-key"})
    assert resp.status_code == 200 and resp.json()["valid"] is True
    nvd.assert_called_once_with("nvd-key")
    ghsa.assert_not_called()


def test_redacted_or_empty_key_is_rejected_without_calling_upstream():
    client = TestClient(_make_app())
    with patch("src.settings.general.router._validate_ghsa_api_key") as ghsa:
        for value in ("", "   ", "[redacted]"):
            resp = client.post("/api/v1/settings/advisory-key/test", json={"source": "ghsa", "apiKey": value})
            assert resp.status_code == 400
    ghsa.assert_not_called()


def test_unknown_source_is_a_validation_error():
    client = TestClient(_make_app())
    resp = client.post("/api/v1/settings/advisory-key/test", json={"source": "osv", "apiKey": "x"})
    assert resp.status_code == 422
