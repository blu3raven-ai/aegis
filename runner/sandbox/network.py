"""Ephemeral egress-denied network for runtime verification.

``docker network create --internal`` gives a bridge with NO route off-box: the
app and the trusted prober can reach each other, but nothing can reach the
internet — the same "no data leaves the box" guarantee as --network=none, while
still allowing the sidecar prober to talk to the target. Always torn down.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager

from runner.sandbox.harness import docker_cli_env
from runner.scanners._subprocess import run_tool

_NET_TIMEOUT_S = 30.0


def create_internal_network(name: str, *, cancel_event: threading.Event | None = None) -> bool:
    code, _out, _err = run_tool(
        ["docker", "network", "create", "--internal", name],
        timeout=_NET_TIMEOUT_S, env=docker_cli_env(), cancel_event=cancel_event,
    )
    return code == 0


def remove_network(name: str) -> None:
    """Best-effort teardown — never raises, so cleanup always runs."""
    run_tool(["docker", "network", "rm", name], timeout=_NET_TIMEOUT_S, env=docker_cli_env())


@contextmanager
def internal_network(name: str, *, cancel_event: threading.Event | None = None):
    """Create an --internal network for the block, guaranteeing teardown. Yields
    the network name on success, or None if creation failed (caller skips)."""
    created = create_internal_network(name, cancel_event=cancel_event)
    try:
        yield name if created else None
    finally:
        if created:
            remove_network(name)
