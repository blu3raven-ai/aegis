"""Unit tests for runner admin write service.

These functions are called by ``src.runner.admin_router`` and raise
``HTTPException`` directly — no GraphQL roundtrip.
"""
from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.runner.admin_service import (  # noqa: E402
    approve,
    generate_token,
    remove,
    revoke,
    rotate_token,
    set_mode,
    update_settings,
)

_NOW = "2025-01-01T00:00:00+00:00"
_RUNNER_ID = "runner-abc123"

_RUNNER_RECORD = {
    "id": _RUNNER_ID,
    "name": "test-runner",
    "status": "approved",
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


def _fake_request() -> MagicMock:
    return MagicMock()


# ── generate_token ─────────────────────────────────────────────────────────

@patch("src.runner.admin_service.create_registration_token", return_value=(
    "raw-token-xyz", {"expiresAt": "2025-01-01T00:10:00+00:00"}
))
def test_generate_token(mock_create):
    result = generate_token()
    assert result["token"] == "raw-token-xyz"
    assert result["expiresAt"] == "2025-01-01T00:10:00+00:00"


# ── set_mode ────────────────────────────────────────────────────────────────

@patch("src.runner.admin_service.write_app_config")
@patch("src.runner.admin_service.read_app_config", return_value={})
def test_set_mode_local(mock_read, mock_write):
    result = set_mode(_fake_request(), "local")
    assert result == {"ok": True, "mode": "local"}
    mock_write.assert_called_once()


@patch("src.runner.admin_service.check_limit")
@patch("src.runner.admin_service.write_app_config")
@patch("src.runner.admin_service.read_app_config", return_value={})
def test_set_mode_remote_checks_license(mock_read, mock_write, mock_check):
    request = _fake_request()
    result = set_mode(request, "remote")
    assert result == {"ok": True, "mode": "remote"}
    mock_check.assert_called_once_with(request, "max_remote_runners", 0)


def test_set_mode_invalid_value():
    with pytest.raises(HTTPException) as exc_info:
        set_mode(_fake_request(), "cloud")
    assert exc_info.value.status_code == 422


# ── update_settings ─────────────────────────────────────────────────────────

@patch("src.runner.admin_service.compute_runner_status", return_value="online")
@patch("src.runner.admin_service._update_runner_settings", return_value={
    **_RUNNER_RECORD, "maxConcurrent": 3
})
def test_update_settings_max_concurrent(mock_update, mock_status):
    result = update_settings(_RUNNER_ID, max_concurrent=3)
    assert result["maxConcurrent"] == 3
    assert result["id"] == _RUNNER_ID


def test_update_settings_no_fields_raises():
    with pytest.raises(HTTPException) as exc_info:
        update_settings(_RUNNER_ID)
    assert exc_info.value.status_code == 422


@patch("src.runner.admin_service._update_runner_settings", return_value=None)
def test_update_settings_not_found(mock_update):
    with pytest.raises(HTTPException) as exc_info:
        update_settings("nonexistent", name="new-name")
    assert exc_info.value.status_code == 404


# ── approve ─────────────────────────────────────────────────────────────────

@patch("src.runner.admin_service.check_limit")
@patch("src.runner.admin_service.list_runners_with_status", return_value=[])
@patch("src.runner.admin_service._approve_runner", return_value=_RUNNER_RECORD)
def test_approve(mock_approve, mock_list, mock_limit):
    result = approve(_fake_request(), _RUNNER_ID)
    assert result == {"ok": True}


@patch("src.runner.admin_service.check_limit")
@patch("src.runner.admin_service.list_runners_with_status", return_value=[])
@patch("src.runner.admin_service._approve_runner", return_value=None)
def test_approve_not_found(mock_approve, mock_list, mock_limit):
    with pytest.raises(HTTPException) as exc_info:
        approve(_fake_request(), "nonexistent")
    assert exc_info.value.status_code == 404


# ── revoke ──────────────────────────────────────────────────────────────────

@patch("src.runner.admin_service._revoke_runner", return_value=_RUNNER_RECORD)
def test_revoke(mock_revoke):
    result = revoke(_RUNNER_ID)
    assert result == {"ok": True}


@patch("src.runner.admin_service._revoke_runner", return_value=None)
def test_revoke_not_found(mock_revoke):
    with pytest.raises(HTTPException) as exc_info:
        revoke("nonexistent")
    assert exc_info.value.status_code == 404


# ── remove ──────────────────────────────────────────────────────────────────

@patch("src.runner.admin_service._remove_runner", return_value=True)
def test_remove(mock_remove):
    result = remove(_RUNNER_ID)
    assert result == {"ok": True}


@patch("src.runner.admin_service._remove_runner", return_value=False)
def test_remove_not_found(mock_remove):
    with pytest.raises(HTTPException) as exc_info:
        remove("nonexistent")
    assert exc_info.value.status_code == 404


# ── rotate_token ────────────────────────────────────────────────────────────

@patch("src.runner.admin_service.rotate_auth_token", return_value=("new-token-abc", None))
def test_rotate_token(mock_rotate):
    result = rotate_token(_RUNNER_ID)
    assert result == {"ok": True, "newToken": "new-token-abc"}


@patch("src.runner.admin_service.rotate_auth_token", return_value=(None, "Runner not found"))
def test_rotate_token_not_found(mock_rotate):
    with pytest.raises(HTTPException) as exc_info:
        rotate_token("nonexistent")
    assert exc_info.value.status_code == 404
