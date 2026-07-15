"""Detonate an untrusted entry flow and capture its egress attempts.

Runs the target on the egress-denied ``--internal`` detonation network with the
honeypot sidecar as its DNS resolver and TCP catch-all. The honeypot logs every
outbound attempt the target makes; nothing reaches the internet (the network has
no route off-box). Any captured event is behavior a benign local setup/skill
never produces — a reverse shell's connect, a DNS-delivered payload's lookup.

The argv builders and log collection here are pure/unit-tested; ``detonate`` is
the thin real-container orchestration (create net → honeypot → target → collect
→ teardown), which only runs under a live runtime.
"""
from __future__ import annotations

import os
import threading

from runner.sandbox.harness import (
    SandboxLimits,
    build_run_args,
    container_cli,
    docker_cli_env,
    runtime_available,
)
from runner.sandbox.honeypot import EgressEvent, parse_egress_log
from runner.sandbox.network import internal_network
from runner.scanners._subprocess import run_tool

_CATCH_PORT = 8888
_INSPECT_TIMEOUT_S = 15.0
_START_TIMEOUT_S = 30.0
# Redirect ALL of the target's outbound TCP to the honeypot's single catch port,
# so a reverse shell to any port lands on the logger. UDP/53 (DNS) is untouched
# and still reaches the resolver. Runs inside the trusted honeypot only.
_HONEYPOT_CMD = (
    "sh", "-c",
    "iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port "
    f"{_CATCH_PORT} && HONEYPOT_SELF_IP=$(hostname -i) "
    "exec python -m runner.sandbox.honeypot",
)


def honeypot_image() -> str:
    """The trusted honeypot image (has python + iptables + the logger). Overridable
    via ``HONEYPOT_IMAGE`` for mirrors / pinned tags on self-hosted runners."""
    return (os.environ.get("HONEYPOT_IMAGE") or "aegis-honeypot:latest").strip() or "aegis-honeypot:latest"


def honeypot_run_args(image: str, *, network: str, name: str) -> list[str]:
    """Detached run of the honeypot. It is TRUSTED (our image), so unlike the
    target it gets ``NET_ADMIN`` to install the TCP redirect — but it stays on the
    egress-denied network and forwards nothing."""
    return [
        container_cli(), "run", "-d", "--rm",
        f"--network={network}",
        "--cap-drop=ALL", "--cap-add=NET_ADMIN",  # only what the redirect needs
        "--security-opt=no-new-privileges",
        "--name", name,
        image, *_HONEYPOT_CMD,
    ]


def target_run_args(
    image: str, cmd, *, network: str, dns_ip: str, name: str,
    limits: SandboxLimits | None = None, runtime: str | None = None,
) -> list[str]:
    """The untrusted target: every hardened control, resolver pointed at the
    honeypot, on the egress-denied network. Not detached — we run the entry flow
    and wait for it under a timeout."""
    return build_run_args(
        image, cmd, network=network, dns=dns_ip, name=name, limits=limits, runtime=runtime,
    )


def container_ip(name: str, network: str, *, cancel_event: threading.Event | None = None) -> str:
    """The container's address on ``network`` (empty string if not resolvable)."""
    fmt = "{{.NetworkSettings.Networks." + network + ".IPAddress}}"
    try:
        code, out, _err = run_tool(
            [container_cli(), "inspect", "-f", fmt, name],
            timeout=_INSPECT_TIMEOUT_S, env=docker_cli_env(), cancel_event=cancel_event,
        )
    except Exception:  # noqa: BLE001
        return ""
    return out.strip() if code == 0 else ""


def collect_egress(honeypot_name: str, *, cancel_event: threading.Event | None = None) -> list[EgressEvent]:
    """Read the honeypot's logged egress attempts. Empty on any failure — a missing
    log means 'observed nothing', never a crash."""
    try:
        code, out, _err = run_tool(
            [container_cli(), "logs", honeypot_name],
            timeout=_INSPECT_TIMEOUT_S, env=docker_cli_env(), cancel_event=cancel_event,
        )
    except Exception:  # noqa: BLE001
        return []
    return parse_egress_log(out) if code == 0 else []


def _remove(name: str) -> None:
    try:
        run_tool([container_cli(), "rm", "-f", name], timeout=_START_TIMEOUT_S, env=docker_cli_env())
    except Exception:  # noqa: BLE001 — teardown never masks the result
        pass


def detonate(
    target_image: str, entry_cmd, *, run_id: str, timeout_s: float = 60.0,
    limits: SandboxLimits | None = None, runtime: str | None = None,
    cancel_event: threading.Event | None = None,
) -> list[EgressEvent] | None:
    """Run ``entry_cmd`` in ``target_image`` on an egress-denied net with the
    honeypot, returning the observed egress attempts. Returns None on any setup
    failure (no runtime, honeypot won't start, no IP) — the caller graceful-skips;
    an empty list means 'ran, observed no egress'."""
    if not runtime_available():
        return None
    hp_name = f"aegis-deto-hp-{run_id}"
    tgt_name = f"aegis-deto-tgt-{run_id}"
    with internal_network(f"aegis-deto-net-{run_id}", cancel_event=cancel_event) as net:
        if net is None:
            return None
        hp_args = honeypot_run_args(honeypot_image(), network=net, name=hp_name)
        try:
            code, _out, _err = run_tool(hp_args, timeout=_START_TIMEOUT_S, env=docker_cli_env(), cancel_event=cancel_event)
            if code != 0:
                return None
            hp_ip = container_ip(hp_name, net, cancel_event=cancel_event)
            if not hp_ip:
                return None
            tgt_args = target_run_args(
                target_image, entry_cmd, network=net, dns_ip=hp_ip, name=tgt_name,
                limits=limits, runtime=runtime,
            )
            # The target may hang (reverse shell holds the socket) — the timeout is
            # the stop condition, not success. We read the honeypot log regardless.
            try:
                run_tool(tgt_args, timeout=timeout_s, env=docker_cli_env(), cancel_event=cancel_event)
            except Exception:  # noqa: BLE001 — target timeout/kill is expected
                pass
            return collect_egress(hp_name, cancel_event=cancel_event)
        finally:
            _remove(tgt_name)
            _remove(hp_name)
