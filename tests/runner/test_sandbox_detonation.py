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
    assert "--user=0:0" in a  # root so iptables works (paired with NET_ADMIN)
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


def test_honeypot_image_prefers_explicit_then_embedded():
    # An explicit HONEYPOT_IMAGE (pinned mirror / pre-loaded tag) wins.
    with patch.dict("os.environ", {"HONEYPOT_IMAGE": "mirror.local/hp:2"}):
        assert det.honeypot_image() == "mirror.local/hp:2"
    # else the locally-provisioned embedded honeypot — no separate registry image.
    with patch.dict("os.environ", {"HONEYPOT_IMAGE": ""}, clear=False):
        assert det.honeypot_image() == det._HONEYPOT_LOCAL_TAG


def test_detonate_skips_when_honeypot_unavailable():
    # ensure_honeypot_image returns None when the host can't detonate → graceful skip.
    with patch("runner.sandbox.detonation.runtime_available", return_value=True), \
         patch("runner.sandbox.detonation.ensure_honeypot_image", return_value=None):
        assert det.detonate("tgt:img", ["setup"], run_id="x") is None


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
         patch("runner.sandbox.detonation.ensure_honeypot_image", return_value="runner:test"), \
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
         patch("runner.sandbox.detonation.ensure_honeypot_image", return_value="runner:test"), \
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
         patch("runner.sandbox.detonation.ensure_honeypot_image", return_value="runner:test"), \
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
         patch("runner.sandbox.detonation.ensure_honeypot_image", return_value="runner:test"), \
         patch("runner.sandbox.detonation.container_ip", return_value=""), \
         patch("runner.sandbox.detonation.run_tool", return_value=(0, "", "")):
        assert det.detonate("tgt:img", ["setup"], run_id="x") is None


# ── ensure_honeypot_image: provisioning (archive → build fallback) + honest probe ──

def _reset_honeypot_cache():
    det._honeypot_ready = None


def test_ensure_honeypot_image_override_short_circuits():
    _reset_honeypot_cache()
    with patch.dict("os.environ", {"HONEYPOT_IMAGE": "mirror.local/hp:9"}), \
         patch("runner.sandbox.detonation._make_honeypot_available") as make, \
         patch("runner.sandbox.detonation._probe_nested_run") as probe:
        assert det.ensure_honeypot_image() == "mirror.local/hp:9"
    make.assert_not_called()   # an explicit image is trusted as-is — no provision, no probe
    probe.assert_not_called()


def test_ensure_prefers_baked_archive_over_build():
    _reset_honeypot_cache()
    with patch.dict("os.environ", {"HONEYPOT_IMAGE": ""}, clear=False), \
         patch("os.path.isfile", return_value=True), \
         patch("runner.sandbox.detonation._image_present", side_effect=[False, True]), \
         patch("runner.sandbox.detonation._load_honeypot_archive", return_value=True) as load, \
         patch("runner.sandbox.detonation._build_embedded_honeypot") as build, \
         patch("runner.sandbox.detonation._probe_nested_run", return_value=True):
        assert det.ensure_honeypot_image() == det._HONEYPOT_LOCAL_TAG
    load.assert_called_once()   # airgap path: loaded the baked archive...
    build.assert_not_called()   # ...and never fell back to a network build


def test_ensure_builds_when_archive_absent():
    _reset_honeypot_cache()
    with patch.dict("os.environ", {"HONEYPOT_IMAGE": ""}, clear=False), \
         patch("os.path.isfile", return_value=False), \
         patch("runner.sandbox.detonation._image_present", return_value=False), \
         patch("runner.sandbox.detonation._load_honeypot_archive") as load, \
         patch("runner.sandbox.detonation._build_embedded_honeypot", return_value=True) as build, \
         patch("runner.sandbox.detonation._probe_nested_run", return_value=True):
        assert det.ensure_honeypot_image() == det._HONEYPOT_LOCAL_TAG
    load.assert_not_called()    # no archive → dev fallback build
    build.assert_called_once()


def test_ensure_none_when_nested_run_probe_fails():
    _reset_honeypot_cache()
    # Image provisions fine, but the host blocks nested containers → honest skip.
    with patch.dict("os.environ", {"HONEYPOT_IMAGE": ""}, clear=False), \
         patch("runner.sandbox.detonation._make_honeypot_available", return_value=True), \
         patch("runner.sandbox.detonation._probe_nested_run", return_value=False):
        assert det.ensure_honeypot_image() is None


def test_ensure_none_when_provisioning_fails():
    _reset_honeypot_cache()
    with patch.dict("os.environ", {"HONEYPOT_IMAGE": ""}, clear=False), \
         patch("runner.sandbox.detonation._make_honeypot_available", return_value=False), \
         patch("runner.sandbox.detonation._probe_nested_run") as probe:
        assert det.ensure_honeypot_image() is None
    probe.assert_not_called()   # never probe if the image isn't even available


def test_ensure_caches_outcome_across_calls():
    _reset_honeypot_cache()
    with patch.dict("os.environ", {"HONEYPOT_IMAGE": ""}, clear=False), \
         patch("runner.sandbox.detonation._make_honeypot_available", return_value=True) as make, \
         patch("runner.sandbox.detonation._probe_nested_run", return_value=True) as probe:
        assert det.ensure_honeypot_image() == det._HONEYPOT_LOCAL_TAG
        assert det.ensure_honeypot_image() == det._HONEYPOT_LOCAL_TAG
    make.assert_called_once()    # provisioned + probed exactly once, then cached
    probe.assert_called_once()


def test_make_honeypot_available_noop_when_already_present():
    with patch("runner.sandbox.detonation._image_present", return_value=True), \
         patch("runner.sandbox.detonation._load_honeypot_archive") as load, \
         patch("runner.sandbox.detonation._build_embedded_honeypot") as build:
        assert det._make_honeypot_available(None) is True
    load.assert_not_called()
    build.assert_not_called()
