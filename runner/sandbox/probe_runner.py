"""Execute a benign ProbeSpec against a running target via a trusted sidecar.

The target app runs on an ``--internal`` network (no egress). This module runs a
SEPARATE, trusted container that we control — a minimal image whose only tool is
``curl`` — on that same network, reaching the app by its container name. That
solves two problems at once: the target image may not ship an HTTP client, and
wrapping an arbitrary entrypoint to probe from inside is fragile.

Only observation verbs (GET/HEAD/OPTIONS) are ever issued — the "enforced
downstream" half of probe.py's benign-lock. A ProbeSpec asking for anything
state-changing is rejected here, not sent.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass

from runner.sandbox.harness import build_run_args, docker_cli_env
from runner.sandbox.probe import ProbeRequest, ProbeSpec
from runner.scanners._subprocess import run_tool

# Verbs that only observe. Anything else is a state change we refuse to issue,
# regardless of what the LLM put in the spec.
_OBSERVATION_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_BODY_SNIPPET_MAX = 2000
_PER_REQUEST_TIMEOUT_S = 15.0


def probe_image() -> str:
    """The trusted sidecar image (has curl). Overridable via ``PROBE_IMAGE`` so a
    self-hosted runner can point at a mirror or a pinned local tag."""
    return (os.environ.get("PROBE_IMAGE") or "curlimages/curl:latest").strip() or "curlimages/curl:latest"


@dataclass(frozen=True)
class ProbeResult:
    """One request's observed outcome. ``status == 0`` means the request never
    produced an HTTP response (rejected, unreachable, or sidecar error) — the
    ``error`` field says which. The verdict resolver treats status 0 as
    inconclusive and never flips a verdict on it."""

    request: ProbeRequest
    status: int = 0
    body_snippet: str = ""
    error: str = ""


def _curl_cmd(url: str, req: ProbeRequest, timeout_s: float) -> list[str]:
    # Body to stdout, then a newline and the numeric status as the final line, so
    # the two are unambiguous to parse. -sS: quiet but surface transport errors.
    cmd = [
        "curl", "-sS", "--max-time", str(int(timeout_s)),
        "-X", req.method, "-o", "-", "-w", "\n%{http_code}", url,
    ]
    for key, value in req.headers.items():
        cmd += ["-H", f"{key}: {value}"]
    return cmd


def _parse(out: str) -> tuple[int, str]:
    """Split curl output into (status, bounded body). Last line is the status."""
    body, _, tail = out.rpartition("\n")
    try:
        status = int(tail.strip())
    except ValueError:
        return 0, body[:_BODY_SNIPPET_MAX]
    return status, body[:_BODY_SNIPPET_MAX]


def run_probe(
    app_name: str,
    spec: ProbeSpec,
    *,
    network: str,
    port: int | None = None,
    image: str | None = None,
    per_request_timeout_s: float = _PER_REQUEST_TIMEOUT_S,
    cancel_event: threading.Event | None = None,
) -> list[ProbeResult]:
    """Run each request in ``spec`` against ``http://<app_name>:<port>`` via the
    trusted sidecar on ``network``. One sidecar container per request (each fully
    hardened via build_run_args). Never raises — every failure mode becomes a
    ProbeResult with ``error`` set, so the caller can graceful-skip."""
    resolved_port = port if port is not None else spec.port
    img = image or probe_image()
    results: list[ProbeResult] = []
    for req in spec.requests:
        method = (req.method or "GET").upper()
        if method not in _OBSERVATION_METHODS:
            results.append(ProbeResult(req, error=f"non-observation method rejected: {method}"))
            continue
        if not resolved_port or resolved_port <= 0:
            results.append(ProbeResult(req, error="unknown target port"))
            continue
        url = f"http://{app_name}:{resolved_port}{req.path or '/'}"
        args = build_run_args(img, _curl_cmd(url, req, per_request_timeout_s), network=network)
        try:
            code, out, err = run_tool(
                args, timeout=per_request_timeout_s + 10.0,
                env=docker_cli_env(), cancel_event=cancel_event,
            )
        except Exception as exc:  # noqa: BLE001 — sidecar launch failed → inconclusive
            results.append(ProbeResult(req, error=f"probe error: {exc}"))
            continue
        status, body = _parse(out)
        if status == 0:
            results.append(ProbeResult(req, body_snippet=body, error=(err or "no HTTP response").strip()[:200]))
        else:
            results.append(ProbeResult(req, status=status, body_snippet=body))
    return results
