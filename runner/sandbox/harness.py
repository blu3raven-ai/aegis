"""Construct and run a HARDENED container invocation for untrusted code.

Threat model: we build a target repo and run it to answer a runtime-verification
question. The scary outcomes — exfiltration, persistence, DoS, lateral movement —
are killed by cheap controls that cost no performance and are applied
UNCONDITIONALLY here. The container-runtime choice (runc / runsc / kata) only
hardens the residual escape risk and is a swappable flag, so v1 ships on the
Docker floor and upgrades to a microVM by config with no code change.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Sequence

from runner.scanners._subprocess import run_tool

# Minimal env the docker CLI itself needs to find its binary and reach the daemon.
# Deliberately EXCLUDES every secret — and it does NOT weaken container isolation,
# because the container's env is controlled separately (we pass no `-e`, so the
# container gets a clean env regardless of what the CLI process can see).
_DOCKER_CLI_ENV_KEYS = (
    "PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY",
)


def docker_cli_env() -> dict[str, str]:
    """Allowlisted env for the docker CLI subprocess (no secrets)."""
    return {k: os.environ[k] for k in _DOCKER_CLI_ENV_KEYS if k in os.environ}


def container_cli() -> str:
    """The container CLI binary. Defaults to ``docker`` but is overridable via
    ``CONTAINER_CLI`` (e.g. ``podman``) — self-hosted runners on a separate env may
    run Podman/rootless, and Podman is CLI-compatible (run/build/network create
    --internal all work). Keeps runtime verification portable off our own infra."""
    return (os.environ.get("CONTAINER_CLI") or "docker").strip() or "docker"


def runtime_available(cli: str | None = None) -> bool:
    """True iff a usable container runtime is present (CLI resolvable + daemon
    reachable). Feeds the graceful-skip matrix so runtime verification NEVER fails
    a scan on a self-hosted runner that can't (or is not allowed to) sandbox — it
    just stays needs_runtime_verification."""
    binary = cli or container_cli()
    try:
        code, _out, _err = run_tool([binary, "version"], timeout=15.0, env=docker_cli_env())
    except Exception:  # noqa: BLE001 — binary missing / daemon down → not available
        return False
    return code == 0


@dataclass(frozen=True)
class SandboxLimits:
    """Anti-DoS caps. Conservative defaults; a build/probe needs little."""

    memory: str = "1g"
    cpus: str = "1.0"
    pids: int = 256
    timeout_s: float = 120.0
    # Writable scratch (rootfs is read-only). Apps that must write live here.
    tmpfs: Sequence[str] = field(default_factory=lambda: ("/tmp",))


def resolve_runtime(get) -> str | None:
    """The container runtime for untrusted code, from ``SANDBOX_RUNTIME``:
    "" → Docker default (runc); "runsc" → gVisor; "kata" → Kata/Firecracker.
    v1 is an explicit opt-in; KVM/runtime auto-detection is a follow-up. Returns
    None for the default runtime (no --runtime flag)."""
    rt = (get("SANDBOX_RUNTIME") or "").strip()
    return rt or None


def build_run_args(
    image: str,
    cmd: Sequence[str],
    *,
    runtime: str | None = None,
    limits: SandboxLimits | None = None,
    env_allow: dict[str, str] | None = None,
    name: str | None = None,
    network: str = "none",
    dns: str | None = None,
) -> list[str]:
    """The hardened ``docker run`` argv. Every control below is MANDATORY:

    - ``--network=<network>``   default ``none`` (no network). For a service that
      must be probed, pass an ``--internal`` docker network name: still no route
      off-box (no egress), but reachable by a sidecar prober on the same network.
    - ``--read-only``           rootfs immutable → cannot persist
    - ``--cap-drop=ALL`` + ``--security-opt=no-new-privileges`` + non-root user
    - ``--memory/--cpus/--pids-limit`` + caller timeout → cannot DoS the runner
    - ``--rm``                  ephemeral
    - NO host env is forwarded — only ``env_allow`` (empty by default) reaches the
      container, so secrets cannot leak in.
    """
    lim = limits or SandboxLimits()
    args: list[str] = [
        container_cli(), "run", "--rm",
        f"--network={network}",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",  # nobody:nogroup
        f"--memory={lim.memory}",
        f"--cpus={lim.cpus}",
        f"--pids-limit={lim.pids}",
    ]
    if runtime:
        args.append(f"--runtime={runtime}")
    if dns:
        # Point name resolution at the detonation honeypot so external lookups
        # resolve to it (and outbound TCP lands on its catch-all) instead of the
        # internet. Only meaningful on an --internal network, which has no egress.
        args.append(f"--dns={dns}")
    for mount in lim.tmpfs:
        args.append(f"--tmpfs={mount}")
    for key, value in (env_allow or {}).items():
        args += ["--env", f"{key}={value}"]
    if name:
        args += ["--name", name]
    args.append(image)
    args.extend(cmd)
    return args


def run_in_sandbox(
    image: str,
    cmd: Sequence[str],
    *,
    runtime: str | None = None,
    limits: SandboxLimits | None = None,
    env_allow: dict[str, str] | None = None,
    cancel_event: threading.Event | None = None,
) -> tuple[int, str, str]:
    """Run ``cmd`` in ``image`` under the hardened profile. Returns
    ``(exit_code, stdout, stderr)``. The docker CLI itself runs with an EMPTY
    environment so no host secret is even visible to the launch, and the
    container env is whatever ``env_allow`` explicitly permits (nothing by
    default)."""
    lim = limits or SandboxLimits()
    args = build_run_args(image, cmd, runtime=runtime, limits=lim, env_allow=env_allow)
    # The CLI needs PATH/DOCKER_HOST to run at all; the CONTAINER still gets a clean
    # env (no -e passed), so secrets can't reach the untrusted workload.
    return run_tool(args, timeout=lim.timeout_s, env=docker_cli_env(), cancel_event=cancel_event)
