"""Egress-denied internal network: --internal, and teardown always runs."""
from __future__ import annotations

from unittest.mock import patch

from runner.sandbox.harness import build_run_args
from runner.sandbox.network import create_internal_network, internal_network, remove_network


def test_create_uses_internal_flag():
    with patch("runner.sandbox.network.run_tool", return_value=(0, "id", "")) as rt:
        assert create_internal_network("probe-net") is True
    args = rt.call_args[0][0]
    assert args[:3] == ["docker", "network", "create"]
    assert "--internal" in args and "probe-net" in args


def test_create_returns_false_on_failure():
    with patch("runner.sandbox.network.run_tool", return_value=(1, "", "err")):
        assert create_internal_network("x") is False


def test_context_manager_tears_down_even_on_exception():
    with patch("runner.sandbox.network.run_tool", return_value=(0, "", "")) as rt:
        try:
            with internal_network("net-1") as net:
                assert net == "net-1"
                raise RuntimeError("boom")
        except RuntimeError:
            pass
    # last call must be the teardown `network rm`
    calls = [c[0][0] for c in rt.call_args_list]
    assert calls[-1][:3] == ["docker", "network", "rm"]
    assert "net-1" in calls[-1]


def test_context_manager_yields_none_and_skips_teardown_on_create_failure():
    with patch("runner.sandbox.network.run_tool", return_value=(1, "", "err")) as rt:
        with internal_network("net-2") as net:
            assert net is None
    # only the failed create ran; no teardown of a network that doesn't exist
    assert all(c[0][0][:3] != ["docker", "network", "rm"] for c in rt.call_args_list)


def test_harness_network_defaults_to_none_but_is_overridable():
    default = build_run_args("img", ["cmd"])
    assert "--network=none" in default
    on_net = build_run_args("img", ["cmd"], network="probe-net")
    assert "--network=probe-net" in on_net
    assert "--network=none" not in on_net
