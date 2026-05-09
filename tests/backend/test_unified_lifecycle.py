"""Tests for the unified lifecycle engine."""
from __future__ import annotations

import pytest

from src.shared.lifecycle import (
    LifecycleHooks,
    ScanContext,
    VALID_DISMISS_REASONS,
)


class FakeDependenciesHooks(LifecycleHooks):
    tool = "dependencies"

    def compute_identity_key(self, raw: dict) -> str:
        return f"{raw.get('repo', '')}::{raw.get('package', '')}::{raw.get('ecosystem', '')}::{raw.get('advisory', '')}"

    def initial_state(self, raw: dict) -> str:
        return "open" if raw.get("has_fix") else "deferred"

    def extract_repo(self, raw: dict) -> str | None:
        return raw.get("repo")

    def extract_severity(self, raw: dict) -> str | None:
        return raw.get("severity")

    def extract_detail(self, raw: dict) -> dict:
        return {"packageName": raw.get("package"), "ecosystem": raw.get("ecosystem")}

    def should_mark_fixed(self, identity_key: str, prev_detail: dict, **kwargs) -> bool:
        return True

    def has_fix(self, raw: dict) -> bool:
        return bool(raw.get("has_fix"))



def test_valid_dismiss_reasons():
    assert "Fix started" in VALID_DISMISS_REASONS
    assert "Risk is tolerable" in VALID_DISMISS_REASONS
    assert "Alert is inaccurate" in VALID_DISMISS_REASONS
    assert "Vulnerable code is not used" in VALID_DISMISS_REASONS


def test_hooks_compute_identity_key():
    hooks = FakeDependenciesHooks()
    raw = {"repo": "acme/api", "package": "requests", "ecosystem": "pip", "advisory": "CVE-1"}
    assert hooks.compute_identity_key(raw) == "acme/api::requests::pip::CVE-1"


def test_hooks_initial_state_with_fix():
    hooks = FakeDependenciesHooks()
    assert hooks.initial_state({"has_fix": True}) == "open"


def test_hooks_initial_state_without_fix():
    hooks = FakeDependenciesHooks()
    assert hooks.initial_state({"has_fix": False}) == "deferred"


def test_scan_context_normalizes_org():
    ctx = ScanContext(tool="dependencies", org="ACME", run_id="run-1")
    assert ctx.org == "acme"
    assert ctx.tool == "dependencies"
    assert ctx.run_id == "run-1"


def test_scan_context_extra_kwargs():
    ctx = ScanContext(tool="code_scanning", org="acme", run_id="run-1", active_rule_ids={"rule1"})
    assert ctx.extra == {"active_rule_ids": {"rule1"}}
