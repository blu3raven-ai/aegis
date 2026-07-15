"""The sandbox invocation must carry every mandatory control. These assertions
ARE the security review of the harness — a missing flag here is a real hole."""
from __future__ import annotations

from unittest.mock import patch

from runner.sandbox.harness import (
    SandboxLimits,
    build_run_args,
    resolve_runtime,
    run_in_sandbox,
)


def _args(**kw):
    return build_run_args("target:latest", ["/probe.sh"], **kw)


def test_network_is_disabled():
    assert "--network=none" in _args()


def test_rootfs_read_only_with_tmpfs_scratch():
    a = _args()
    assert "--read-only" in a
    assert "--tmpfs=/tmp" in a


def test_all_capabilities_dropped_and_no_new_privileges():
    a = _args()
    assert "--cap-drop=ALL" in a
    assert "--security-opt=no-new-privileges" in a


def test_runs_as_non_root():
    assert "--user=65534:65534" in _args()


def test_resource_caps_present():
    a = _args()
    assert any(x.startswith("--memory=") for x in a)
    assert any(x.startswith("--cpus=") for x in a)
    assert any(x.startswith("--pids-limit=") for x in a)


def test_ephemeral():
    assert "--rm" in _args()


def test_no_host_env_forwarded_by_default():
    # Nothing but explicitly-allowed vars may reach the container.
    a = _args()
    assert "--env" not in a
    a2 = _args(env_allow={"PORT": "8080"})
    assert "--env" in a2 and "PORT=8080" in a2
    # A secret-looking var only appears if the CALLER explicitly allows it.
    assert not any("SECRET" in x for x in _args())


def test_image_and_cmd_come_last():
    a = _args()
    i = a.index("target:latest")
    assert a[i + 1] == "/probe.sh"
    # no flags after the image
    assert all(not x.startswith("--") for x in a[i:])


def test_runtime_flag_only_when_selected():
    assert not any(x.startswith("--runtime=") for x in _args())
    assert "--runtime=runsc" in _args(runtime="runsc")
    assert "--runtime=kata" in _args(runtime="kata")


def test_resolve_runtime_from_env():
    assert resolve_runtime({"SANDBOX_RUNTIME": "runsc"}.get) == "runsc"
    assert resolve_runtime({"SANDBOX_RUNTIME": " "}.get) is None
    assert resolve_runtime({}.get) is None


def test_custom_limits_flow_through():
    lim = SandboxLimits(memory="512m", cpus="0.5", pids=64, timeout_s=30.0)
    a = build_run_args("t", ["x"], limits=lim)
    assert "--memory=512m" in a and "--cpus=0.5" in a and "--pids-limit=64" in a


def test_run_in_sandbox_launches_with_minimal_cli_env_and_timeout():
    lim = SandboxLimits(timeout_s=42.0)
    with patch.dict("os.environ", {"PATH": "/usr/bin", "AWS_SECRET_ACCESS_KEY": "x"}, clear=True), \
         patch("runner.sandbox.harness.run_tool", return_value=(0, "ok", "")) as rt:
        code, out, err = run_in_sandbox("t", ["x"], limits=lim)
    assert code == 0
    _, kwargs = rt.call_args
    # The CLI gets PATH (so docker runs) but NO secret from the host env.
    assert kwargs["env"].get("PATH") == "/usr/bin"
    assert "AWS_SECRET_ACCESS_KEY" not in kwargs["env"]
    assert kwargs["timeout"] == 42.0     # hard wall-clock cap enforced
    passed_args = rt.call_args[0][0]
    assert "--network=none" in passed_args  # the hardened argv is what ran


# --- self-hosted portability: configurable CLI + availability detection ---

def test_container_cli_defaults_to_docker():
    with patch.dict("os.environ", {}, clear=True):
        from runner.sandbox.harness import container_cli
        assert container_cli() == "docker"


def test_container_cli_honors_env_override():
    from runner.sandbox.harness import container_cli
    with patch.dict("os.environ", {"CONTAINER_CLI": "podman"}, clear=True):
        assert container_cli() == "podman"
    with patch.dict("os.environ", {"CONTAINER_CLI": "  "}, clear=True):
        assert container_cli() == "docker"  # blank falls back


def test_build_run_args_uses_configured_cli():
    from runner.sandbox.harness import build_run_args
    with patch.dict("os.environ", {"CONTAINER_CLI": "podman"}, clear=True):
        a = build_run_args("img", ["c"])
    assert a[0] == "podman" and a[1] == "run"


def test_runtime_available_true_when_version_succeeds():
    from runner.sandbox.harness import runtime_available
    with patch("runner.sandbox.harness.run_tool", return_value=(0, "Docker 27", "")):
        assert runtime_available() is True


def test_runtime_available_false_when_cli_missing_or_daemon_down():
    from runner.sandbox.harness import runtime_available
    with patch("runner.sandbox.harness.run_tool", side_effect=FileNotFoundError):
        assert runtime_available() is False   # binary not on PATH (self-hosted w/o docker)
    with patch("runner.sandbox.harness.run_tool", return_value=(1, "", "cannot connect")):
        assert runtime_available() is False   # daemon down / not permitted
