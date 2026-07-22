"""Tests for the hunter's runtime_probe tool and its registry gating.

The sandbox serve+probe calls (run_probe / run_gvisor_probe) are always mocked --
no app is actually served in a unit test.
"""
from __future__ import annotations

from runner.sandbox.gvisor_probe import ServePlan
from runner.sandbox.probe import ProbeRequest
from runner.sandbox.probe_runner import ProbeResult
from runner.verification import pipeline
from runner.verification.agents.base import AgentResult
from runner.verification.tools import runtime as rt
from runner.verification.tools.runtime import make_runtime_probe_tool


def _dockerfile(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nEXPOSE 8000\nCMD [\"python\", \"app.py\"]\n")


# (a) no recipe -> unavailable string ---------------------------------------


def test_no_recipe_returns_unavailable(tmp_path):
    tool = make_runtime_probe_tool(str(tmp_path))
    out = tool.handler({"requests": [{"path": "/admin"}]})
    assert out == "// runtime_probe unavailable: no runnable app (no Dockerfile/recipe)"


# (b) non-observation method dropped ----------------------------------------


def test_non_observation_method_dropped(tmp_path, monkeypatch):
    _dockerfile(tmp_path)
    # Only a POST requested -> nothing observable remains.
    monkeypatch.setattr(rt, "runtime_available", lambda: True)
    tool = make_runtime_probe_tool(str(tmp_path))
    out = tool.handler({"requests": [{"path": "/x", "method": "POST"}]})
    assert "only GET/HEAD/OPTIONS are allowed" in out
    assert "dropped POST /x" in out


# (c) no runtime -> unavailable string --------------------------------------


def test_no_container_runtime_returns_unavailable(tmp_path, monkeypatch):
    _dockerfile(tmp_path)
    monkeypatch.setattr(rt, "runtime_available", lambda: False)
    monkeypatch.setattr(rt, "runsc_available", lambda: False)
    tool = make_runtime_probe_tool(str(tmp_path))
    out = tool.handler({"requests": [{"path": "/admin"}]})
    assert out == "// runtime_probe unavailable: no container runtime"


# (d) a mocked successful serve+probe formats results -----------------------


def test_successful_probe_formats_results(tmp_path, monkeypatch):
    _dockerfile(tmp_path)
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()

    fake = [
        ProbeResult(ProbeRequest(method="GET", path="/admin"), status=200, body_snippet="secret data\nhere"),
        ProbeResult(ProbeRequest(method="GET", path="/missing"), error="no HTTP response"),
    ]

    monkeypatch.setattr(rt, "runtime_available", lambda: False)
    monkeypatch.setattr(rt, "runsc_available", lambda: True)
    monkeypatch.setattr(rt, "detect_serve", lambda _df: ServePlan(ecosystem="python", cmd=("python", "app.py")))
    monkeypatch.setattr(rt, "prepare_rootfs", lambda eco, repo, run_id: str(rootfs))
    captured = {}

    def _fake_gvisor_probe(rootfs_dir, cmd, spec, *, port, run_id, **kw):
        captured["port"] = port
        captured["paths"] = [r.path for r in spec.requests]
        return fake

    monkeypatch.setattr(rt, "run_gvisor_probe", _fake_gvisor_probe)

    tool = make_runtime_probe_tool(str(tmp_path))
    out = tool.handler({"requests": [{"path": "/admin"}, {"path": "/missing"}]})

    assert "GET /admin -> HTTP 200 :: secret data here" in out
    assert "GET /missing -> no response" in out
    assert captured["port"] == 8000  # EXPOSE hint threaded through
    assert captured["paths"] == ["/admin", "/missing"]


def test_probe_that_never_serves_returns_unavailable(tmp_path, monkeypatch):
    _dockerfile(tmp_path)
    monkeypatch.setattr(rt, "runtime_available", lambda: False)
    monkeypatch.setattr(rt, "runsc_available", lambda: True)
    monkeypatch.setattr(rt, "detect_serve", lambda _df: ServePlan(ecosystem="python", cmd=("python", "app.py")))
    monkeypatch.setattr(rt, "prepare_rootfs", lambda eco, repo, run_id: str(tmp_path / "rootfs"))
    (tmp_path / "rootfs").mkdir()
    monkeypatch.setattr(rt, "run_gvisor_probe", lambda *a, **k: None)

    tool = make_runtime_probe_tool(str(tmp_path))
    out = tool.handler({"requests": [{"path": "/admin"}]})
    assert out == "// runtime_probe unavailable: app did not serve"


def test_handler_never_raises(tmp_path, monkeypatch):
    _dockerfile(tmp_path)
    monkeypatch.setattr(rt, "runtime_available", lambda: True)

    def _boom(*a, **k):
        raise RuntimeError("build exploded")

    monkeypatch.setattr(rt, "build_image", _boom)
    tool = make_runtime_probe_tool(str(tmp_path))
    out = tool.handler({"requests": [{"path": "/x"}]})
    assert out == "// runtime_probe unavailable: app did not serve"


# (e) registry includes runtime_probe only when runtime_enabled -------------


_GOOD_HUNTER = (
    '{"exploit_chain":"x reaches y","evidence":['
    '{"file":"a.py","line":1,"snippet":"x","kind":"source"}]}'
)


def _capture_investigate(monkeypatch):
    seen = {}

    def _fake(*, system_prompt, user_task, tools, llm, max_turns=8,
              max_tokens_per_turn=1000, budget=None):
        seen["tools"] = tools.names()
        return AgentResult(
            final_message=_GOOD_HUNTER, tool_calls=[], tokens_in=1, tokens_out=1,
            turns=1, stopped_reason="completed",
        )

    monkeypatch.setattr(pipeline, "investigate", _fake)
    return seen


def test_hunter_registry_includes_runtime_probe_when_enabled(monkeypatch):
    seen = _capture_investigate(monkeypatch)
    pipeline.run_tp_reasoning(
        {"file": "a.py", "line": 1}, "1: x", None,
        llm=object(), repo_root="/x", runtime_enabled=True,
    )
    assert "runtime_probe" in seen["tools"]
    assert "grep_repo" in seen["tools"]


def test_hunter_registry_omits_runtime_probe_by_default(monkeypatch):
    seen = _capture_investigate(monkeypatch)
    pipeline.run_tp_reasoning(
        {"file": "a.py", "line": 1}, "1: x", None,
        llm=object(), repo_root="/x",
    )
    assert "runtime_probe" not in seen["tools"]
    assert "grep_repo" in seen["tools"]
