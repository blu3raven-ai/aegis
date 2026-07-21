"""The orchestrator must be strictly opt-in and graceful-skip on every missing
precondition — it may only rewrite a verdict on a clean probe result, and must
never raise or downgrade a finding it couldn't prove."""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

from runner.sandbox import sast_runtime as orch
from runner.sandbox.runtime_verdict import RuntimeResolution


class _Env:
    def __init__(self, **vars):
        self._v = vars

    def get(self, key, default=""):
        return self._v.get(key, default)


def _finding(verdict="needs_runtime_verification", question="GET /admin without auth returns 200?"):
    return {
        "id": "f1",
        "verdict": verdict,
        "evidence": [{"kind": "runtime_log", "snippet": question, "source": "runtime_check"}],
        "verification_metadata": {"runtime_question": question},
    }


def _run(findings, env, **overrides):
    """Run with every external dependency stubbed to a benign default; overrides
    swap in the behavior under test."""
    defaults = {
        "runtime_available": lambda: True,
        "detect_recipe": lambda root: object(),
        "build_image": lambda root, tag, cancel_event=None: True,
        "detect_port": lambda recipe: 8080,
        "start_app": lambda *a, **k: True,
        "wait_ready": lambda *a, **k: True,
        "stop_app": lambda name: None,
        "generate_probe": lambda q, *, llm, port_hint=None, context=None: _Spec(),
        "run_probe": lambda *a, **k: ["result"],
        "resolve_runtime_verdict": lambda results: RuntimeResolution(
            "confirmed", {"kind": "runtime_log", "snippet": "GET /admin (no credential) → 200",
                          "source": "runtime_check"}, "unauth 2xx"),
    }
    defaults.update(overrides)

    @contextmanager
    def fake_net(name, *, cancel_event=None):
        yield "net"

    with patch.multiple("runner.sandbox.sast_runtime",
                        internal_network=fake_net,
                        **{k: v for k, v in defaults.items()}):
        return orch.verify_findings_at_runtime(findings, "/repo", env=env, llm=object())


class _Spec:
    port = 8080
    requests = [object()]


def test_disabled_is_noop():
    f = [_finding()]
    out = _run(f, _Env())  # RUNTIME_VERIFY unset
    assert out[0]["verdict"] == "needs_runtime_verification"


def test_no_llm_is_noop():
    f = _finding()
    with patch.object(orch, "runtime_available", lambda: True):
        out = orch.verify_findings_at_runtime([f], "/repo", env=_Env(RUNTIME_VERIFY="1"), llm=None)
    assert out[0]["verdict"] == "needs_runtime_verification"


def test_runtime_unavailable_is_noop():
    out = _run([_finding()], _Env(RUNTIME_VERIFY="1"), runtime_available=lambda: False)
    assert out[0]["verdict"] == "needs_runtime_verification"


def test_no_dockerfile_is_noop():
    out = _run([_finding()], _Env(RUNTIME_VERIFY="1"), detect_recipe=lambda root: None)
    assert out[0]["verdict"] == "needs_runtime_verification"


def test_build_failure_is_noop():
    out = _run([_finding()], _Env(RUNTIME_VERIFY="1"),
               build_image=lambda root, tag, cancel_event=None: False)
    assert out[0]["verdict"] == "needs_runtime_verification"


def test_app_never_ready_is_noop_but_tears_down():
    calls = []
    out = _run([_finding()], _Env(RUNTIME_VERIFY="1"),
               wait_ready=lambda *a, **k: False,
               stop_app=lambda name: calls.append(name))
    assert out[0]["verdict"] == "needs_runtime_verification"
    assert calls  # teardown ran even though we skipped


def test_findings_with_no_runtime_question_are_ignored():
    f = _finding(question="")
    f["verification_metadata"] = {}
    out = _run([f], _Env(RUNTIME_VERIFY="1"))
    assert out[0]["verdict"] == "needs_runtime_verification"


def test_happy_path_rewrites_verdict_and_appends_evidence():
    f = _finding()
    out = _run([f], _Env(RUNTIME_VERIFY="1"))
    assert out[0]["verdict"] == "confirmed"
    assert len(out[0]["evidence"]) == 2  # original runtime_log + the resolution log
    assert out[0]["verification_metadata"]["runtime_resolution"] == "unauth 2xx"


def test_inconclusive_leaves_finding_untouched():
    out = _run([_finding()], _Env(RUNTIME_VERIFY="1"),
               resolve_runtime_verdict=lambda results: RuntimeResolution(
                   "needs_runtime_verification", None, "no conclusive runtime signal"))
    assert out[0]["verdict"] == "needs_runtime_verification"
    assert len(out[0]["evidence"]) == 1  # nothing appended


# --- Tier 2: standalone gVisor when the nested container runtime is absent ---

class _Recipe:
    dockerfile = "/repo/Dockerfile"


def _run_gvisor(findings, env, **overrides):
    """Tier-2 path: nested runtime absent, runsc present. Stubs the gVisor probe
    machinery to a benign default; overrides swap in the behavior under test."""
    defaults = {
        "runtime_available": lambda: False,        # Tier 1 unavailable
        "runsc_available": lambda cancel_event=None: True,
        "detect_recipe": lambda root: _Recipe(),
        "detect_port": lambda recipe: 8080,
        "detect_serve": lambda dockerfile: _Serve(),
        "prepare_rootfs": lambda eco, root, rid: "/fake-rootfs",
        "generate_probe": lambda q, *, llm, port_hint=None, context=None: _Spec(),
        "run_gvisor_probe": lambda *a, **k: ["result"],
        "resolve_runtime_verdict": lambda results: RuntimeResolution(
            "confirmed", {"kind": "runtime_log", "snippet": "GET /admin (no credential) -> 200",
                          "source": "runtime_check"}, "unauth 2xx"),
    }
    defaults.update(overrides)
    with patch.multiple("runner.sandbox.sast_runtime", **defaults):
        return orch.verify_findings_at_runtime(findings, "/repo", env=env, llm=object())


class _Serve:
    ecosystem = "python"
    cmd = ("python", "app.py")


def test_tier1_available_does_not_use_gvisor():
    # runtime_available True -> Tier 1 runs, gVisor probe is never called.
    called = []
    out = _run([_finding()], _Env(RUNTIME_VERIFY="1"),
               run_probe=lambda *a, **k: called.append("t1") or ["result"])
    assert out[0]["verdict"] == "confirmed"
    assert called == ["t1"]  # Tier 1 sidecar probe, not the gVisor path


def test_gvisor_tier_taken_when_runtime_absent_but_runsc_present():
    out = _run_gvisor([_finding()], _Env(RUNTIME_VERIFY="1"))
    assert out[0]["verdict"] == "confirmed"
    assert len(out[0]["evidence"]) == 2
    assert out[0]["verification_metadata"]["runtime_resolution"] == "unauth 2xx"


def test_no_tier_available_is_noop():
    out = _run_gvisor([_finding()], _Env(RUNTIME_VERIFY="1"),
                      runsc_available=lambda cancel_event=None: False)
    assert out[0]["verdict"] == "needs_runtime_verification"


def test_gvisor_no_serve_plan_is_noop():
    out = _run_gvisor([_finding()], _Env(RUNTIME_VERIFY="1"),
                      detect_serve=lambda dockerfile: None)
    assert out[0]["verdict"] == "needs_runtime_verification"


def test_gvisor_no_base_rootfs_is_noop():
    out = _run_gvisor([_finding()], _Env(RUNTIME_VERIFY="1"),
                      prepare_rootfs=lambda eco, root, rid: None)
    assert out[0]["verdict"] == "needs_runtime_verification"


def test_gvisor_probe_skip_leaves_finding_untouched():
    out = _run_gvisor([_finding()], _Env(RUNTIME_VERIFY="1"),
                      run_gvisor_probe=lambda *a, **k: None)
    assert out[0]["verdict"] == "needs_runtime_verification"
    assert len(out[0]["evidence"]) == 1
