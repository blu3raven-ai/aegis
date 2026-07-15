"""The detonation runner must keep the untrusted target fully hardened + egress-
denied while the trusted honeypot (only) gets NET_ADMIN, and must graceful-skip
(return None) on any setup failure rather than raise."""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

from runner.sandbox import detonation as det
from runner.sandbox.honeypot import EgressEvent


def test_honeypot_run_args_detached_with_only_net_admin():
    a = det.honeypot_run_args("hp:img", network="net", name="hp")
    assert "-d" in a and "--network=net" in a
    assert "--cap-drop=ALL" in a and "--cap-add=NET_ADMIN" in a  # trusted, minimal add
    assert "--security-opt=no-new-privileges" in a
    assert "REDIRECT" in " ".join(a)  # installs the TCP catch redirect


def test_target_run_args_hardened_egress_denied_dns_at_honeypot():
    a = det.target_run_args("tgt:img", ["setup"], network="net", dns_ip="10.9.0.2", name="tgt")
    # every mandatory control from the sandbox floor
    assert "--network=net" in a and "--read-only" in a and "--cap-drop=ALL" in a
    assert "--user=65534:65534" in a and "--security-opt=no-new-privileges" in a
    # NEVER gets NET_ADMIN — only the honeypot does
    assert "--cap-add=NET_ADMIN" not in a
    # resolver points at the honeypot
    assert "--dns=10.9.0.2" in a
    assert a[-1] == "setup" and "tgt:img" in a


def test_collect_egress_parses_honeypot_logs():
    log = "\n".join([
        EgressEvent("dns", "_axiom-config.evil.example", "TXT").to_json(),
        EgressEvent("tcp", "10.9.0.2:4443", "").to_json(),
    ])
    with patch("runner.sandbox.detonation.run_tool", return_value=(0, log, "")):
        events = det.collect_egress("hp")
    assert [e.proto for e in events] == ["dns", "tcp"]
    assert events[0].target == "_axiom-config.evil.example"


def test_collect_egress_empty_on_failure_never_raises():
    with patch("runner.sandbox.detonation.run_tool", side_effect=OSError("boom")):
        assert det.collect_egress("hp") == []


def test_container_ip_empty_when_inspect_fails():
    with patch("runner.sandbox.detonation.run_tool", return_value=(1, "", "no such object")):
        assert det.container_ip("hp", "net") == ""


def test_container_ip_uses_index_for_hyphenated_network_names():
    # Our networks are named aegis-deto-net-<id>; a Go template can't dot-access a
    # map key with hyphens, so the inspect format MUST use `index`. (A live run
    # caught this; the stub can't see the template, so assert its shape here.)
    captured = {}

    def fake(args, **kw):
        captured["args"] = args
        return (0, "10.0.0.2", "")

    with patch("runner.sandbox.detonation.run_tool", side_effect=fake):
        assert det.container_ip("hp", "aegis-deto-net-abc") == "10.0.0.2"
    fmt = captured["args"][captured["args"].index("-f") + 1]
    assert "index" in fmt and '"aegis-deto-net-abc"' in fmt
    assert ".Networks.aegis-deto-net-abc" not in fmt  # the broken dot form is gone


def test_honeypot_image_env_override():
    assert det.honeypot_image()
    with patch.dict("os.environ", {"HONEYPOT_IMAGE": "mirror.local/hp:2"}):
        assert det.honeypot_image() == "mirror.local/hp:2"


def test_detonate_skips_when_no_runtime():
    with patch("runner.sandbox.detonation.runtime_available", return_value=False):
        assert det.detonate("tgt:img", ["setup"], run_id="x") is None


def test_detonate_returns_events_and_tears_down():
    removed = []

    @contextmanager
    def fake_net(name, *, cancel_event=None):
        yield "net"

    def fake_run(args, **kw):
        if args[1] == "logs":
            return (0, EgressEvent("tcp", "10.9.0.2:4443", "").to_json(), "")
        if args[1] == "rm":
            removed.append(args[-1])
        return (0, "", "")

    with patch("runner.sandbox.detonation.runtime_available", return_value=True), \
         patch("runner.sandbox.detonation.internal_network", fake_net), \
         patch("runner.sandbox.detonation.container_ip", return_value="10.9.0.2"), \
         patch("runner.sandbox.detonation.run_tool", side_effect=fake_run):
        events = det.detonate("tgt:img", ["setup"], run_id="x")

    assert events and events[0].proto == "tcp"
    assert any("tgt" in n for n in removed) and any("hp" in n for n in removed)  # both torn down


def test_detonate_skips_when_honeypot_fails_to_start():
    @contextmanager
    def fake_net(name, *, cancel_event=None):
        yield "net"

    # honeypot `run -d` returns non-zero → cannot observe → skip (None), still tears down.
    with patch("runner.sandbox.detonation.runtime_available", return_value=True), \
         patch("runner.sandbox.detonation.internal_network", fake_net), \
         patch("runner.sandbox.detonation.run_tool", return_value=(1, "", "start failed")):
        assert det.detonate("tgt:img", ["setup"], run_id="x") is None


def test_detonate_collects_even_when_target_errors():
    # The target hanging/erroring (reverse shell holds the socket, or a timeout
    # kill) is expected — we still read the honeypot log and return what it saw.
    @contextmanager
    def fake_net(name, *, cancel_event=None):
        yield "net"

    def fake_run(args, **kw):
        if args[1] == "run" and "-d" not in args:  # the target run
            raise OSError("target killed on timeout")
        if args[1] == "logs":
            return (0, EgressEvent("dns", "evil.example", "TXT").to_json(), "")
        return (0, "", "")

    with patch("runner.sandbox.detonation.runtime_available", return_value=True), \
         patch("runner.sandbox.detonation.internal_network", fake_net), \
         patch("runner.sandbox.detonation.container_ip", return_value="10.9.0.2"), \
         patch("runner.sandbox.detonation.run_tool", side_effect=fake_run):
        events = det.detonate("tgt:img", ["setup"], run_id="x")
    assert events and events[0].target == "evil.example"


def test_detonate_skips_when_honeypot_has_no_ip():
    @contextmanager
    def fake_net(name, *, cancel_event=None):
        yield "net"

    with patch("runner.sandbox.detonation.runtime_available", return_value=True), \
         patch("runner.sandbox.detonation.internal_network", fake_net), \
         patch("runner.sandbox.detonation.container_ip", return_value=""), \
         patch("runner.sandbox.detonation.run_tool", return_value=(0, "", "")):
        assert det.detonate("tgt:img", ["setup"], run_id="x") is None
