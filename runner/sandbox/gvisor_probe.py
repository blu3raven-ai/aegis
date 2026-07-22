"""Standalone gVisor (runsc) tier for the SAST runtime-verification probe.

The nested-container SAST tier (``sast_runtime`` Tier 1) needs a container daemon
to build an image, stand it up on an ``--internal`` network, and reach it from a
sidecar. That whole path is unavailable where nested rootless podman cannot run
(Docker Desktop's LinuxKit VM blocks nested multi-ID user namespaces). This tier
fills that gap the same way ``gvisor.py`` does for detonation: no daemon, no
socket, just ``runsc`` inside a throwaway network namespace.

The shape differs from detonation because the goal is the OPPOSITE. Detonation
watches for egress and hijacks all traffic to a honeypot; here the trusted probe
must actually REACH the app, so:

- the app runs from a baked base rootfs + the repo overlaid at ``/app`` (no nested
  build, which is exactly the step that fails on Docker Desktop) under
  ``runsc run --network=host`` inside an ``unshare --net --map-root-user`` netns;
- that netns is ROUTELESS with only loopback up and NO DNAT, so the untrusted app
  cannot phone home, yet the in-netns probe reaches it on ``127.0.0.1``;
- the probe is our own ``curl`` run as a plain subprocess joined to the same netns
  (trusted, so no sandbox), issuing ONLY the observation verbs ``probe_runner``
  already enforces.

The builders below are pure and unit-tested; ``run_gvisor_probe`` is the thin
real-namespace orchestration, guarded so ANY failure returns None and the caller
graceful-skips (never a false verdict).
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from runner.sandbox.gvisor import (
    _runsc_state_root,
    oci_config,
    runsc_available,
    runsc_binary,
    runsc_run_argv,
    unshare_argv,
)
from runner.sandbox.probe import ProbeSpec
from runner.sandbox.probe_runner import (
    _OBSERVATION_METHODS,
    _curl_cmd,
    _parse,
    ProbeResult,
)
from runner.scanners._subprocess import run_tool

logger = logging.getLogger(__name__)

_LOOPBACK = "127.0.0.1"
_READY_ATTEMPTS = 30
_READY_INTERVAL_S = 1
_APP_TIMEOUT_S = 90.0
_PER_REQUEST_TIMEOUT_S = 15.0

# FROM base image -> baked-rootfs ecosystem key (see gvisor.prepare_rootfs). Only
# the ecosystems we bake a base for are runnable; anything else -> skip.
_FROM_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)", re.IGNORECASE | re.MULTILINE)
_INSTR_RE = re.compile(r"^\s*(CMD|ENTRYPOINT)\s+(.*)$", re.IGNORECASE)


@dataclass(frozen=True)
class ServePlan:
    """How to serve the target from a baked base rootfs: which base to use and the
    argv that starts the app. Derived from the repo's Dockerfile, best-effort."""

    ecosystem: str          # "npm" | "python" | "shell"
    cmd: tuple[str, ...]    # argv that starts the server, run with cwd=/app


def _ecosystem_for(base_image: str) -> str | None:
    img = base_image.lower()
    if "node" in img:
        return "npm"
    if "python" in img:
        return "python"
    if any(t in img for t in ("debian", "ubuntu", "alpine", "busybox")):
        return "shell"
    return None


def _parse_argv(rest: str) -> tuple[str, ...]:
    """A Dockerfile CMD/ENTRYPOINT operand as argv: JSON-array (exec) form first,
    else a shell-word split of the shell form. Empty on failure."""
    rest = rest.strip()
    if rest.startswith("["):
        try:
            arr = json.loads(rest)
        except ValueError:
            return ()
        if isinstance(arr, list) and all(isinstance(x, str) for x in arr):
            return tuple(arr)
        return ()
    try:
        return tuple(shlex.split(rest))
    except ValueError:
        return ()


def detect_serve(dockerfile_path: str) -> ServePlan | None:
    """Best-effort serve plan from the repo's Dockerfile, or None (-> skip).

    Uses the base image for the ecosystem and ENTRYPOINT + CMD for the start argv
    (standard Docker semantics: ENTRYPOINT is prefixed to CMD). None whenever we
    cannot pin a baked ecosystem or a start command -- a missing plan is a skip,
    never a guess.
    """
    try:
        text = Path(dockerfile_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    from_matches = _FROM_RE.findall(text)
    if not from_matches:
        return None
    ecosystem = _ecosystem_for(from_matches[-1])
    if ecosystem is None:
        return None
    entrypoint: tuple[str, ...] = ()
    cmd: tuple[str, ...] = ()
    for line in text.splitlines():
        m = _INSTR_RE.match(line)
        if not m:
            continue
        argv = _parse_argv(m.group(2))
        if m.group(1).upper() == "ENTRYPOINT":
            entrypoint = argv
        else:
            cmd = argv
    start = (*entrypoint, *cmd)
    if not start:
        return None
    return ServePlan(ecosystem=ecosystem, cmd=start)


def _ready_curl_argv(port: int) -> list[str]:
    """A silent GET that succeeds (exit 0) once the app answers HTTP on loopback."""
    return ["curl", "-sf", "-o", "/dev/null", "--max-time", "2",
            f"http://{_LOOPBACK}:{port}/"]


def _observation_requests(spec: ProbeSpec) -> list:
    """The spec's requests, dropping any non-observation verb -- the same
    benign-lock ``probe_runner`` enforces, reused rather than re-listed."""
    keep = []
    for req in spec.requests:
        if (req.method or "GET").upper() in _OBSERVATION_METHODS:
            keep.append(req)
    return keep


def probe_netns_script(
    *, bundle_dir: str, container_id: str, port: int,
    curl_argvs: Sequence[Sequence[str]], result_dir: str, app_timeout_s: float,
    ready_attempts: int = _READY_ATTEMPTS, ready_interval_s: int = _READY_INTERVAL_S,
) -> str:
    """The shell run INSIDE ``unshare --net --map-root-user``: bring up a ROUTELESS
    loopback (no default route off-box, no DNAT), start the app under runsc, poll
    until it answers, run each trusted probe curl on loopback into a per-request
    result file, then tear down. Egress stays denied because the only interface is
    loopback; the probe reaches the app there. Every interpolated argv is
    shell-quoted."""
    run = " ".join(shlex.quote(a) for a in runsc_run_argv(bundle_dir, container_id))
    ready = " ".join(shlex.quote(a) for a in _ready_curl_argv(port))
    delete = " ".join(
        shlex.quote(a) for a in [runsc_binary(), "--rootless", "--root", _runsc_state_root(), "delete", "--force", container_id]
    )
    lines = [
        "set -u",
        "ip link set lo up",
        f"timeout {int(app_timeout_s)} {run} >/dev/null 2>&1 &",
        "APP=$!",
        f"i=0; while [ $i -lt {int(ready_attempts)} ]; do "
        f"if {ready} >/dev/null 2>&1; then break; fi; "
        f"sleep {int(ready_interval_s)}; i=$((i+1)); done",
    ]
    for idx, argv in enumerate(curl_argvs):
        c = " ".join(shlex.quote(a) for a in argv)
        out = shlex.quote(os.path.join(result_dir, str(idx)))
        lines.append(f"{c} > {out} 2>/dev/null || true")
    lines += [
        "kill $APP 2>/dev/null || true",
        f"{delete} 2>/dev/null || true",
    ]
    return "\n".join(lines) + "\n"


def _results_from(requests: list, result_dir: str, resolved_port: int) -> list[ProbeResult]:
    """Read each request's captured curl output back into a ProbeResult, reusing
    ``probe_runner._parse``. A missing/empty file is an inconclusive status-0
    result -- never flips a verdict."""
    results: list[ProbeResult] = []
    for idx, req in enumerate(requests):
        path = os.path.join(result_dir, str(idx))
        try:
            out = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            results.append(ProbeResult(req, error="no probe response"))
            continue
        status, body = _parse(out)
        if status == 0:
            results.append(ProbeResult(req, body_snippet=body, error="no HTTP response"))
        else:
            results.append(ProbeResult(req, status=status, body_snippet=body))
    return results


def run_gvisor_probe(
    rootfs_dir: str, start_cmd: Sequence[str], spec: ProbeSpec, *,
    port: int | None, run_id: str, cwd: str = "/app",
    app_timeout_s: float = _APP_TIMEOUT_S, cancel_event=None,
) -> list[ProbeResult] | None:
    """Serve ``start_cmd`` from ``rootfs_dir`` under standalone gVisor in a routeless
    netns and run ``spec``'s observation requests against it on loopback.

    Returns the per-request ProbeResults, or None on ANY setup failure (runtime
    unavailable, no usable port, no observation request, namespace/orchestration
    error) so the caller graceful-skips. Trusted probe, so no sandbox around curl;
    the app is the only thing under gVisor."""
    if not runsc_available(cancel_event):
        return None
    resolved_port = port if (port and port > 0) else spec.port
    if not resolved_port or resolved_port <= 0:
        return None
    requests = _observation_requests(spec)
    if not requests:
        return None

    bundle = tempfile.mkdtemp(prefix=f"aegis-gvprobe-{run_id}-")
    result_dir = tempfile.mkdtemp(prefix=f"aegis-gvprobe-out-{run_id}-")
    try:
        os.symlink(os.path.abspath(rootfs_dir), os.path.join(bundle, "rootfs"))
        with open(os.path.join(bundle, "config.json"), "w") as fh:
            json.dump(oci_config(start_cmd, cwd=cwd), fh)
        curl_argvs = [
            _curl_cmd(f"http://{_LOOPBACK}:{resolved_port}{req.path or '/'}",
                      req, _PER_REQUEST_TIMEOUT_S)
            for req in requests
        ]
        script = probe_netns_script(
            bundle_dir=bundle, container_id=f"aegis-gvprobe-{run_id}",
            port=resolved_port, curl_argvs=curl_argvs, result_dir=result_dir,
            app_timeout_s=app_timeout_s,
        )
        sfd, spath = tempfile.mkstemp(prefix=f"aegis-gvprobe-run-{run_id}-", suffix=".sh")
        try:
            with os.fdopen(sfd, "w") as fh:
                fh.write(script)
            run_tool(
                unshare_argv(spath), timeout=app_timeout_s + 30.0, cancel_event=cancel_event,
            )
        finally:
            try:
                os.unlink(spath)
            except OSError:
                pass
        return _results_from(requests, result_dir, resolved_port)
    except Exception:  # noqa: BLE001 - any failure means graceful-skip, never a false verdict
        logger.warning("[sast-runtime] gVisor probe errored, skipping", exc_info=True)
        return None
    finally:
        shutil.rmtree(bundle, ignore_errors=True)
        shutil.rmtree(result_dir, ignore_errors=True)
