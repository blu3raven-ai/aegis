"""Tests for the onboarding REST endpoints.

Follows the same mini-FastAPI + TestClient pattern as test_notification_admin_router.py.
The service layer is monkeypatched so no DB is touched.
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.onboarding.models import OnboardingState, StepState
from src.onboarding.router import router as onboarding_router


ORG = "example-org"


def _make_default_state() -> OnboardingState:
    return OnboardingState()


def _make_dismissed_state() -> OnboardingState:
    s = OnboardingState()
    s.dismissed = True
    for step_id in s.steps:
        s.steps[step_id].completed = True
    return s


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(
        "src.onboarding.router.require_permission",
        lambda req, perm: None,
    )
    mini = FastAPI()
    mini.include_router(onboarding_router)
    return TestClient(mini, raise_server_exceptions=True)


# ── GET /state ────────────────────────────────────────────────────────────────


def test_get_state_returns_200_with_state(client):
    with patch("src.onboarding.router.get_state", return_value=_make_default_state()):
        resp = client.get(f"/api/v1/onboarding/state?org_id={ORG}")

    assert resp.status_code == 200
    body = resp.json()
    assert "state" in body
    assert body["state"]["dismissed"] is False
    assert "steps" in body["state"]


def test_get_state_includes_all_steps(client):
    with patch("src.onboarding.router.get_state", return_value=_make_default_state()):
        resp = client.get(f"/api/v1/onboarding/state?org_id={ORG}")

    steps = resp.json()["state"]["steps"]
    for step_id in ["connect_source", "pick_repos", "smoke_test"]:
        assert step_id in steps


def test_get_state_reflects_dismissed(client):
    with patch("src.onboarding.router.get_state", return_value=_make_dismissed_state()):
        resp = client.get(f"/api/v1/onboarding/state?org_id={ORG}")

    assert resp.json()["state"]["dismissed"] is True


# ── POST /state/step/{step_id} ────────────────────────────────────────────────


def test_complete_step_returns_updated_state(client):
    updated = _make_default_state()
    updated.steps["connect_source"].completed = True

    with patch("src.onboarding.router.complete_step", return_value=updated) as mock_svc:
        resp = client.post(
            f"/api/v1/onboarding/state/step/connect_source?org_id={ORG}",
            json={"action": "complete", "data": {}},
        )

    assert resp.status_code == 200
    assert resp.json()["state"]["steps"]["connect_source"]["completed"] is True
    mock_svc.assert_called_once_with(ORG, "connect_source", {})


def test_skip_step_calls_skip_service(client):
    updated = _make_default_state()
    updated.steps["smoke_test"].skipped = True

    with patch("src.onboarding.router.skip_step", return_value=updated) as mock_svc:
        resp = client.post(
            f"/api/v1/onboarding/state/step/smoke_test?org_id={ORG}",
            json={"action": "skip"},
        )

    assert resp.status_code == 200
    mock_svc.assert_called_once_with(ORG, "smoke_test")


def test_dismiss_step_calls_dismiss_service(client):
    dismissed = _make_dismissed_state()

    with patch("src.onboarding.router.dismiss", return_value=dismissed) as mock_svc:
        resp = client.post(
            f"/api/v1/onboarding/state/step/smoke_test?org_id={ORG}",
            json={"action": "dismiss"},
        )

    assert resp.status_code == 200
    assert resp.json()["state"]["dismissed"] is True
    mock_svc.assert_called_once_with(ORG)


def test_invalid_step_id_returns_404(client):
    resp = client.post(
        f"/api/v1/onboarding/state/step/nonexistent?org_id={ORG}",
        json={"action": "complete", "data": {}},
    )
    assert resp.status_code == 404


def test_invalid_action_returns_422(client):
    resp = client.post(
        f"/api/v1/onboarding/state/step/welcome?org_id={ORG}",
        json={"action": "bogus"},
    )
    assert resp.status_code == 422
