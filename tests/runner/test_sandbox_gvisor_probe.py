"""The standalone-gVisor SAST probe tier: pure builders (serve-plan parse, netns
script, result parse) and the graceful-skip contract on missing preconditions."""
from __future__ import annotations

import os
import tempfile
from unittest.mock import patch

from runner.sandbox import gvisor_probe as gp
from runner.sandbox.probe import ProbeRequest, ProbeSpec


# --- detect_serve (Dockerfile -> serve plan) ---

def _dockerfile(body: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".Dockerfile")
    with os.fdopen(fd, "w") as fh:
        fh.write(body)
    return path


def test_detect_serve_python_exec_cmd():
    p = _dockerfile('FROM python:3.12-slim\nEXPOSE 8080\nCMD ["python", "app.py"]\n')
    plan = gp.detect_serve(p)
    assert plan is not None
    assert plan.ecosystem == "python" and plan.cmd == ("python", "app.py")


def test_detect_serve_combines_entrypoint_and_cmd():
    p = _dockerfile('FROM node:20-slim\nENTRYPOINT ["node"]\nCMD ["server.js"]\n')
    plan = gp.detect_serve(p)
    assert plan.ecosystem == "npm" and plan.cmd == ("node", "server.js")


def test_detect_serve_shell_form_cmd():
    p = _dockerfile("FROM debian:stable-slim\nCMD python3 -m http.server 8000\n")
    plan = gp.detect_serve(p)
    assert plan.ecosystem == "shell"
    assert plan.cmd == ("python3", "-m", "http.server", "8000")


def test_detect_serve_uses_last_from_stage():
    p = _dockerfile('FROM golang:1 AS build\nFROM python:3.12-slim\nCMD ["python","x.py"]\n')
    assert gp.detect_serve(p).ecosystem == "python"


def test_detect_serve_none_for_unbaked_base():
    p = _dockerfile('FROM golang:1.22\nCMD ["/app/server"]\n')
    assert gp.detect_serve(p) is None


def test_detect_serve_none_without_start_command():
    p = _dockerfile("FROM python:3.12-slim\nEXPOSE 8080\n")
    assert gp.detect_serve(p) is None


def test_detect_serve_none_for_missing_file():
    assert gp.detect_serve("/no/such/Dockerfile") is None


# --- pure argv / verb-filter builders ---

def test_ready_curl_argv_hits_loopback():
    a = gp._ready_curl_argv(8080)
    assert a[0] == "curl" and "-sf" in a and "http://127.0.0.1:8080/" in a


def test_observation_requests_drops_state_changing_verbs():
    spec = ProbeSpec(port=80, requests=[
        ProbeRequest(method="GET", path="/a"),
        ProbeRequest(method="POST", path="/b"),
        ProbeRequest(method="HEAD", path="/c"),
    ])
    kept = gp._observation_requests(spec)
    assert [r.path for r in kept] == ["/a", "/c"]  # POST dropped, reusing the allowlist


# --- netns script (routeless loopback, no DNAT, quoted curls) ---

def test_probe_netns_script_is_routeless_and_runs_app_and_probes():
    s = gp.probe_netns_script(
        bundle_dir="/b", container_id="cid", port=8080,
        curl_argvs=[["curl", "http://127.0.0.1:8080/admin"]],
        result_dir="/out", app_timeout_s=42,
    )
    assert "ip link set lo up" in s
    # routeless: never adds a default route off-box, never DNATs anything
    assert "route add default" not in s and "DNAT" not in s
    assert "--network=host" in s          # app shares the netns
    assert "timeout 42" in s              # app run is time-bounded
    assert "http://127.0.0.1:8080/admin" in s
    assert "/out/0" in s                  # per-request result capture


def test_probe_netns_script_quotes_injected_curl_argv():
    s = gp.probe_netns_script(
        bundle_dir="/b", container_id="cid", port=80,
        curl_argvs=[["curl", "http://127.0.0.1:80/;rm -rf /"]],
        result_dir="/out", app_timeout_s=10,
    )
    # the metacharacters are quoted, not left bare for the shell to interpret
    assert "'http://127.0.0.1:80/;rm -rf /'" in s


# --- result parse ---

def test_results_from_parses_status_and_marks_missing():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "0"), "w") as fh:
        fh.write("BODYTEXT\n200")
    # index 1 file intentionally absent -> inconclusive
    reqs = [ProbeRequest(path="/a"), ProbeRequest(path="/b")]
    results = gp._results_from(reqs, d, 8080)
    assert results[0].status == 200 and "BODYTEXT" in results[0].body_snippet
    assert results[1].status == 0 and results[1].error


# --- run_gvisor_probe graceful-skip contract ---

def test_run_gvisor_probe_none_when_runsc_unavailable():
    with patch.object(gp, "runsc_available", return_value=False):
        assert gp.run_gvisor_probe("/rootfs", ("python", "app.py"),
                                   ProbeSpec(port=8080, requests=[ProbeRequest()]),
                                   port=8080, run_id="r") is None


def test_run_gvisor_probe_none_without_port():
    with patch.object(gp, "runsc_available", return_value=True):
        assert gp.run_gvisor_probe("/rootfs", ("python", "app.py"),
                                   ProbeSpec(port=0, requests=[ProbeRequest()]),
                                   port=None, run_id="r") is None


def test_run_gvisor_probe_none_without_observation_request():
    with patch.object(gp, "runsc_available", return_value=True):
        spec = ProbeSpec(port=8080, requests=[ProbeRequest(method="POST")])
        assert gp.run_gvisor_probe("/rootfs", ("python", "app.py"), spec,
                                   port=8080, run_id="r") is None
