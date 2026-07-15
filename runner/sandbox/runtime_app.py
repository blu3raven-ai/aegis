"""Start / await / stop the target app container for runtime verification.

The app runs DETACHED on an ``--internal`` network with its own unmodified
entrypoint and every hardened control from build_run_args (read-only, cap-drop,
non-root, resource caps, no secrets, egress denied). Readiness is polled from the
trusted curl sidecar on the same network — any HTTP response means the server is
up. Teardown is force-remove and best-effort, so it runs even on the error path.
"""
from __future__ import annotations

import re
import threading
import time
from pathlib import Path

from runner.sandbox.build import BuildRecipe
from runner.sandbox.harness import build_run_args, container_cli, docker_cli_env
from runner.sandbox.probe_runner import probe_image
from runner.scanners._subprocess import run_tool

_READY_CAP_S = 30.0
_READY_INTERVAL_S = 1.0
_START_TIMEOUT_S = 30.0
_EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+(\d+)", re.IGNORECASE | re.MULTILINE)


def detect_port(recipe: BuildRecipe) -> int | None:
    """First ``EXPOSE <port>`` in the Dockerfile, else None. A best-effort hint —
    the probe still falls back to the LLM-inferred port and skips if neither works."""
    try:
        text = Path(recipe.dockerfile).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _EXPOSE_RE.search(text)
    return int(m.group(1)) if m else None


def run_app_args(image: str, *, network: str, name: str, runtime: str | None = None) -> list[str]:
    """Detached hardened run of the app's own entrypoint (no cmd override). No port
    is published to the host — the sidecar reaches the app over the internal
    network by name, so nothing is exposed off-box."""
    args = build_run_args(image, [], runtime=runtime, name=name, network=network)
    args.insert(2, "-d")  # after [cli, "run", ...]
    return args


def start_app(
    image: str, *, network: str, name: str, runtime: str | None = None,
    cancel_event: threading.Event | None = None,
) -> bool:
    """Start the app detached. True if the run command accepted it (not proof of
    readiness — poll wait_ready next)."""
    args = run_app_args(image, network=network, name=name, runtime=runtime)
    code, _out, _err = run_tool(args, timeout=_START_TIMEOUT_S, env=docker_cli_env(), cancel_event=cancel_event)
    return code == 0


def _probe_once(name: str, port: int, *, network: str, cancel_event: threading.Event | None) -> str:
    cmd = ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "2",
           f"http://{name}:{port}/"]
    args = build_run_args(probe_image(), cmd, network=network)
    try:
        _code, out, _err = run_tool(args, timeout=10.0, env=docker_cli_env(), cancel_event=cancel_event)
    except Exception:  # noqa: BLE001
        return "000"
    return (out or "").strip()


def wait_ready(
    name: str, port: int, *, network: str, cap_s: float = _READY_CAP_S,
    interval_s: float = _READY_INTERVAL_S, cancel_event: threading.Event | None = None,
    _sleep=time.sleep, _now=time.monotonic,
) -> bool:
    """Poll until the app answers HTTP (any status but 000) or the cap elapses.
    A non-000 status = the server is up; we don't care what it returns yet."""
    if not port or port <= 0:
        return False
    deadline = _now() + cap_s
    while _now() < deadline:
        if cancel_event is not None and cancel_event.is_set():
            return False
        if _probe_once(name, port, network=network, cancel_event=cancel_event) not in ("", "000"):
            return True
        _sleep(interval_s)
    return False


def stop_app(name: str) -> None:
    """Force-remove the app container. Best-effort — never raises."""
    try:
        run_tool([container_cli(), "rm", "-f", name], timeout=_START_TIMEOUT_S, env=docker_cli_env())
    except Exception:  # noqa: BLE001 — teardown must never mask the real result
        pass
