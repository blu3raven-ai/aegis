"""Unit tests for OnboardingService state transitions.

run_db is monkeypatched to return an in-memory dict so tests run without
a live Postgres. The patch replaces read_app_config / write_app_config
because the service uses those helpers (same pattern as settings tests).
"""
from __future__ import annotations

import pytest
from unittest.mock import patch

from src.onboarding.models import OnboardingState, STEP_ORDER


# ── Helpers ────────────────────────────────────────────────────────────────────

def _patch_config(existing: dict | None = None):
    """Context manager that stubs read/write_app_config."""
    store: dict = existing or {}

    def _read():
        return {"onboarding": store.get("onboarding")} if store else {}

    written: list[dict] = []

    def _write(config, event_type="settings.updated"):
        store["onboarding"] = config.get("onboarding")
        written.append(config)

    return patch("src.onboarding.service.read_app_config", _read), \
           patch("src.onboarding.service.write_app_config", _write), \
           written


# ── get_state ──────────────────────────────────────────────────────────────────

def test_get_state_returns_default_for_new_org():
    from src.onboarding import service as svc
    with patch.object(svc, "read_app_config", return_value={}), \
         patch.object(svc, "write_app_config", return_value=None):
        state = svc.get_state("example-org")

    assert isinstance(state, OnboardingState)
    assert state.dismissed is False
    for step_id in STEP_ORDER:
        assert state.steps[step_id].completed is False


def test_get_state_deserialises_existing_blob():
    existing_blob = {
        "dismissed": False,
        "steps": {
            "welcome": {"completed": True, "skipped": False, "data": {}},
            "connect_source": {"completed": False, "skipped": False, "data": {}},
            "smoke_test": {"completed": False, "skipped": False, "data": {}},
            "alerts": {"completed": False, "skipped": False, "data": {}},
            "policy": {"completed": False, "skipped": False, "data": {}},
        },
    }
    from src.onboarding import service as svc
    with patch.object(svc, "read_app_config", return_value={"onboarding": existing_blob}), \
         patch.object(svc, "write_app_config", return_value=None):
        state = svc.get_state("example-org")

    assert state.steps["welcome"].completed is True
    assert state.steps["connect_source"].completed is False


# ── complete_step ──────────────────────────────────────────────────────────────

def test_complete_step_marks_step_completed():
    written: list[dict] = []
    store: dict = {}

    def _read():
        return {"onboarding": store.get("onboarding")}

    def _write(cfg, event_type="settings.updated"):
        store["onboarding"] = cfg.get("onboarding")
        written.append(cfg)

    from src.onboarding import service as svc
    with patch.object(svc, "read_app_config", _read), \
         patch.object(svc, "write_app_config", _write):
        state = svc.complete_step("example-org", "welcome", {})

    assert state.steps["welcome"].completed is True
    assert len(written) == 1


def test_complete_step_stores_data_payload():
    store: dict = {}

    def _read():
        return {"onboarding": store.get("onboarding")}

    def _write(cfg, event_type="settings.updated"):
        store["onboarding"] = cfg.get("onboarding")

    from src.onboarding import service as svc
    with patch.object(svc, "read_app_config", _read), \
         patch.object(svc, "write_app_config", _write):
        state = svc.complete_step("example-org", "connect_source", {"provider": "github"})

    assert state.steps["connect_source"].data == {"provider": "github"}


# ── skip_step ──────────────────────────────────────────────────────────────────

def test_skip_step_marks_skipped_not_completed():
    store: dict = {}

    def _read():
        return {"onboarding": store.get("onboarding")}

    def _write(cfg, event_type="settings.updated"):
        store["onboarding"] = cfg.get("onboarding")

    from src.onboarding import service as svc
    with patch.object(svc, "read_app_config", _read), \
         patch.object(svc, "write_app_config", _write):
        state = svc.skip_step("example-org", "smoke_test")

    assert state.steps["smoke_test"].skipped is True
    assert state.steps["smoke_test"].completed is False


# ── dismiss ────────────────────────────────────────────────────────────────────

def test_dismiss_sets_dismissed_flag():
    store: dict = {}

    def _read():
        return {"onboarding": store.get("onboarding")}

    def _write(cfg, event_type="settings.updated"):
        store["onboarding"] = cfg.get("onboarding")

    from src.onboarding import service as svc
    with patch.object(svc, "read_app_config", _read), \
         patch.object(svc, "write_app_config", _write):
        state = svc.dismiss("example-org")

    assert state.dismissed is True


# ── is_complete ────────────────────────────────────────────────────────────────

def test_is_complete_false_by_default():
    from src.onboarding import service as svc
    with patch.object(svc, "read_app_config", return_value={}), \
         patch.object(svc, "write_app_config", return_value=None):
        result = svc.is_complete("example-org")

    assert result is False


def test_is_complete_true_after_dismiss():
    dismissed_blob = {
        "dismissed": True,
        "steps": {
            step: {"completed": True, "skipped": False, "data": {}}
            for step in ["welcome", "connect_source", "smoke_test", "alerts", "policy"]
        },
    }
    from src.onboarding import service as svc
    with patch.object(svc, "read_app_config", return_value={"onboarding": dismissed_blob}), \
         patch.object(svc, "write_app_config", return_value=None):
        result = svc.is_complete("example-org")

    assert result is True
