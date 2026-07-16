"""The orchestrator triages first, then acts: not-worth → nothing; worth + off →
recommend; worth + on → detonate. It only ever ADDs a finding and never raises."""
from __future__ import annotations

from unittest.mock import patch

from runner.sandbox import detonation_orchestrator as orch
from runner.sandbox.entry import DetonationEntry
from runner.sandbox.honeypot import EgressEvent

_ENTRY = DetonationEntry(cmd=("npm", "run", "postinstall", "--silent"),
                         ecosystem="npm", source="package.json:scripts.postinstall")


class _Env:
    def __init__(self, **v):
        self._v = v

    def get(self, key, default=""):
        return self._v.get(key, default)


def _run(env, *, static_hits=1, **over):
    # static_hits=1 by default so triage flags the target as worth detonating; the
    # detonation-path stubs below then exercise the runtime flow.
    defaults = {
        "runtime_available": lambda: True,
        "detect_entry": lambda root: _ENTRY,
        "_build": lambda recipe, tag, cancel_event: True,
        "detonate": lambda tag, cmd, *, run_id, cancel_event=None: [
            EgressEvent("dns", "_axiom-config.evil.example", "TXT")],
    }
    defaults.update(over)
    with patch.multiple("runner.sandbox.detonation_orchestrator", **defaults):
        return orch.detonate_repo("/repo", env=env, run_id="x", static_hits=static_hits)


def test_dockerfile_body_per_ecosystem():
    assert "--ignore-scripts" in orch.dockerfile_body("npm")
    assert "debian" in orch.dockerfile_body("shell")
    assert orch.dockerfile_body("python") is None


# --- triage gate ---

def test_not_worth_is_noop_even_with_entry():
    # entry present but no risk signal → don't run code, don't nag.
    assert _run(_Env(DETONATE="1"), static_hits=0) == []


def test_no_entry_is_noop():
    assert _run(_Env(DETONATE="1"), detect_entry=lambda root: None) == []


def test_worth_but_detonation_off_recommends():
    findings = _run(_Env(), static_hits=2)  # DETONATE unset, but a risk signal fired
    assert len(findings) == 1
    f = findings[0]
    assert f["check_id"] == "AGENT_DETONATION_RECOMMENDED"
    assert f["severity"] == "low" and f["verdict"] is None
    assert any(s["kind"] == "static_hit" for s in f["evidence"]["signals"])


# --- detonation path (worth + enabled) ---

def test_no_runtime_is_noop_when_enabled():
    assert _run(_Env(DETONATE="1"), runtime_available=lambda: False) == []


def test_unsupported_ecosystem_is_noop():
    py = DetonationEntry(cmd=("python", "-m", "x"), ecosystem="python", source="x")
    assert _run(_Env(DETONATE="1"), detect_entry=lambda root: py) == []


def test_build_failure_is_noop():
    assert _run(_Env(DETONATE="1"), _build=lambda recipe, tag, cancel_event: False) == []


def test_detonate_skip_is_noop():
    assert _run(_Env(DETONATE="1"), detonate=lambda *a, **k: None) == []


def test_no_egress_adds_no_finding():
    assert _run(_Env(DETONATE="1"), detonate=lambda *a, **k: []) == []


def test_egress_produces_a_confirmed_critical_finding():
    findings = _run(_Env(DETONATE="1"))
    assert len(findings) == 1
    f = findings[0]
    assert f["check_id"] == "AGENT_DETONATION_EGRESS"
    assert f["severity"] == "critical" and f["verdict"] == "confirmed"
    assert f["file"] == "package.json"
    assert "_axiom-config.evil.example" in f["evidence"]["runtime_log"][0]["snippet"]


def test_build_helper_maps_exit_code_and_never_raises():
    from runner.sandbox.build import BuildRecipe
    recipe = BuildRecipe(dockerfile="/tmp/x.Dockerfile", context="/repo")
    with patch("runner.sandbox.detonation_orchestrator.run_tool", return_value=(0, "", "")):
        assert orch._build(recipe, "tag", None) is True
    with patch("runner.sandbox.detonation_orchestrator.run_tool", return_value=(1, "", "err")):
        assert orch._build(recipe, "tag", None) is False
    with patch("runner.sandbox.detonation_orchestrator.run_tool", side_effect=OSError("boom")):
        assert orch._build(recipe, "tag", None) is False


def test_obfuscated_entry_body_triages_as_worth_when_off():
    # An obfuscated setup entry alone (no skill marker, no static hit) is now a
    # risk signal — previously entry_obfuscated was wired nowhere.
    obf = DetonationEntry(cmd=("sh", "setup.sh"), ecosystem="shell",
                          source="setup.sh", body="eval(atob('cGF5bG9hZA=='))")
    findings = _run(_Env(), static_hits=0, detect_entry=lambda root: obf)
    assert len(findings) == 1 and findings[0]["check_id"] == "AGENT_DETONATION_RECOMMENDED"
