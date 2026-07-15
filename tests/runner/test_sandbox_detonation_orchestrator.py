"""The detonation orchestrator must be strictly opt-in and graceful-skip on every
missing precondition, only ever ADD a runtime-confirmed finding, and never raise."""
from __future__ import annotations

from unittest.mock import patch

from runner.sandbox import detonation_orchestrator as orch
from runner.sandbox.entry import DetonationEntry
from runner.sandbox.honeypot import EgressEvent


class _Env:
    def __init__(self, **v):
        self._v = v

    def get(self, key, default=""):
        return self._v.get(key, default)


_ENTRY = DetonationEntry(cmd=("npm", "run", "postinstall", "--silent"),
                         ecosystem="npm", source="package.json:scripts.postinstall")


def _run(env, **over):
    defaults = {
        "runtime_available": lambda: True,
        "detect_entry": lambda root: _ENTRY,
        "_build": lambda recipe, tag, cancel_event: True,
        "detonate": lambda tag, cmd, *, run_id, cancel_event=None: [
            EgressEvent("dns", "_axiom-config.evil.example", "TXT")],
    }
    defaults.update(over)
    with patch.multiple("runner.sandbox.detonation_orchestrator", **defaults):
        return orch.detonate_repo("/repo", env=env, run_id="x")


def test_dockerfile_body_per_ecosystem():
    assert "--ignore-scripts" in orch.dockerfile_body("npm")  # deps without firing scripts
    assert "debian" in orch.dockerfile_body("shell")
    assert orch.dockerfile_body("python") is None  # unsupported → skip


def test_disabled_is_noop():
    assert _run(_Env()) == []  # DETONATE unset


def test_no_runtime_is_noop():
    assert _run(_Env(DETONATE="1"), runtime_available=lambda: False) == []


def test_no_entry_is_noop():
    assert _run(_Env(DETONATE="1"), detect_entry=lambda root: None) == []


def test_unsupported_ecosystem_is_noop():
    py_entry = DetonationEntry(cmd=("python", "-m", "x"), ecosystem="python", source="x")
    assert _run(_Env(DETONATE="1"), detect_entry=lambda root: py_entry) == []


def test_build_failure_is_noop():
    assert _run(_Env(DETONATE="1"), _build=lambda recipe, tag, cancel_event: False) == []


def test_detonate_skip_is_noop():
    assert _run(_Env(DETONATE="1"), detonate=lambda *a, **k: None) == []


def test_no_egress_adds_no_finding():
    assert _run(_Env(DETONATE="1"), detonate=lambda *a, **k: []) == []


def test_build_helper_maps_exit_code_and_never_raises():
    from runner.sandbox.build import BuildRecipe
    recipe = BuildRecipe(dockerfile="/tmp/x.Dockerfile", context="/repo")
    with patch("runner.sandbox.detonation_orchestrator.run_tool", return_value=(0, "", "")):
        assert orch._build(recipe, "tag", None) is True
    with patch("runner.sandbox.detonation_orchestrator.run_tool", return_value=(1, "", "err")):
        assert orch._build(recipe, "tag", None) is False
    with patch("runner.sandbox.detonation_orchestrator.run_tool", side_effect=OSError("boom")):
        assert orch._build(recipe, "tag", None) is False  # graceful-skip, no raise


def test_egress_produces_a_confirmed_critical_finding():
    findings = _run(_Env(DETONATE="1"))
    assert len(findings) == 1
    f = findings[0]
    assert f["check_id"] == "AGENT_DETONATION_EGRESS"
    assert f["severity"] == "critical" and f["verdict"] == "confirmed"
    assert f["file"] == "package.json"
    assert "_axiom-config.evil.example" in f["evidence"]["runtime_log"][0]["snippet"]
