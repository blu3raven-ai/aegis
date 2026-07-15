"""The prober must (1) issue only observation verbs, (2) inherit every hardened
control, (3) parse status/body robustly, and (4) never raise. These assertions
are the security review of the sidecar execution path."""
from __future__ import annotations

from unittest.mock import patch

from runner.sandbox.probe import ProbeRequest, ProbeSpec
from runner.sandbox.probe_runner import probe_image, run_probe


def _spec(*reqs: ProbeRequest, port: int = 8080) -> ProbeSpec:
    return ProbeSpec(port=port, requests=list(reqs))


def test_observation_only_methods_are_rejected_without_running_anything():
    called = []
    with patch("runner.sandbox.probe_runner.run_tool", side_effect=lambda *a, **k: called.append(a)):
        results = run_probe("app", _spec(ProbeRequest(method="POST", path="/admin")), network="net")
    assert called == []  # a state-changing verb is never issued
    assert results[0].status == 0
    assert "non-observation method rejected" in results[0].error


def test_hardened_controls_present_on_the_sidecar():
    captured = {}

    def fake(args, **kwargs):
        captured["args"] = args
        return (0, "hi\n200", "")

    with patch("runner.sandbox.probe_runner.run_tool", side_effect=fake):
        run_probe("app", _spec(ProbeRequest(path="/x")), network="internal-net")
    a = captured["args"]
    assert "--network=internal-net" in a
    assert "--read-only" in a and "--cap-drop=ALL" in a
    assert "--security-opt=no-new-privileges" in a and "--user=65534:65534" in a
    assert "http://app:8080/x" in a


def test_status_and_body_are_parsed():
    with patch("runner.sandbox.probe_runner.run_tool", return_value=(0, "welcome admin\n200", "")):
        r = run_probe("app", _spec(ProbeRequest(path="/admin")), network="net")[0]
    assert r.status == 200 and r.body_snippet == "welcome admin" and r.error == ""


def test_body_snippet_is_bounded():
    big = "A" * 5000
    with patch("runner.sandbox.probe_runner.run_tool", return_value=(0, f"{big}\n200", "")):
        r = run_probe("app", _spec(ProbeRequest(path="/x")), network="net")[0]
    assert len(r.body_snippet) == 2000


def test_unparseable_status_is_inconclusive():
    with patch("runner.sandbox.probe_runner.run_tool", return_value=(7, "curl: (7) refused", "connect fail")):
        r = run_probe("app", _spec(ProbeRequest(path="/x")), network="net")[0]
    assert r.status == 0 and r.error  # never a false verdict on a transport failure


def test_unknown_port_skips():
    with patch("runner.sandbox.probe_runner.run_tool") as rt:
        r = run_probe("app", _spec(ProbeRequest(path="/x"), port=0), network="net")[0]
    rt.assert_not_called()
    assert r.status == 0 and "unknown target port" in r.error


def test_subprocess_failure_never_raises():
    with patch("runner.sandbox.probe_runner.run_tool", side_effect=OSError("boom")):
        r = run_probe("app", _spec(ProbeRequest(path="/x")), network="net")[0]
    assert r.status == 0 and "probe error" in r.error


def test_probe_image_env_override():
    assert probe_image()  # a default always exists
    with patch.dict("os.environ", {"PROBE_IMAGE": "mirror.local/curl:8"}):
        assert probe_image() == "mirror.local/curl:8"
