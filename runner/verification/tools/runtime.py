"""runtime_probe tool: serve the target app in a sandbox and observe how it
actually responds to the hunter's requests, mid-investigation.

Reuses the opt-in runtime-verification machinery (the same RUNTIME_VERIFY gate as
the separate runtime pass): build + serve on an --internal network reached by the
trusted curl sidecar (Tier 1), or serve from a baked base rootfs under standalone
gVisor in a routeless netns (Tier 2). Only observation verbs (GET/HEAD/OPTIONS)
are ever issued. The handler NEVER raises: every failure path returns an
explanatory ``//`` string so the agent loop keeps going.
"""
from __future__ import annotations

import logging
import shutil
import uuid

from runner.sandbox.build import build_image, detect_recipe
from runner.sandbox.gvisor import prepare_rootfs, runsc_available
from runner.sandbox.gvisor_probe import detect_serve, run_gvisor_probe
from runner.sandbox.harness import runtime_available
from runner.sandbox.network import internal_network
from runner.sandbox.probe import ProbeRequest, ProbeSpec
from runner.sandbox.probe_runner import _OBSERVATION_METHODS, run_probe
from runner.sandbox.runtime_app import detect_port, start_app, stop_app, wait_ready
from runner.verification.tools.base import Tool

logger = logging.getLogger(__name__)

_BODY_SNIPPET_MAX = 300
_MAX_REQUESTS = 6


def _build_spec(requests, port_hint: int | None) -> tuple[ProbeSpec | None, list[str]]:
    """Turn the agent's requested paths into a ProbeSpec of observation requests.

    Returns ``(spec, notes)``. ``spec`` is None when nothing observable remains;
    ``notes`` records any dropped state-changing verb (or a truncation) so the
    model sees why."""
    items = requests if isinstance(requests, list) else []
    notes: list[str] = []
    if len(items) > _MAX_REQUESTS:
        notes.append(f"// only the first {_MAX_REQUESTS} requests were run (batch fewer)")
        items = items[:_MAX_REQUESTS]
    keep: list[ProbeRequest] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        method = str(item.get("method") or "GET").upper()
        path = str(item.get("path") or "/")
        if method not in _OBSERVATION_METHODS:
            notes.append(f"// dropped {method} {path}: only GET/HEAD/OPTIONS are allowed")
            continue
        keep.append(ProbeRequest(method=method, path=path))
    if not keep:
        return None, notes
    return ProbeSpec(port=port_hint or 0, requests=keep), notes


def _format(results) -> str:
    lines: list[str] = []
    for r in results:
        verb = r.request.method
        path = r.request.path or "/"
        if r.status and r.status > 0:
            body = (r.body_snippet or "").replace("\n", " ")[:_BODY_SNIPPET_MAX]
            lines.append(f"{verb} {path} -> HTTP {r.status} :: {body}")
        else:
            lines.append(f"{verb} {path} -> no response")
    return "\n".join(lines)


def _serve_and_probe_container(repo_root, spec, port_hint, *, run_id):
    """Tier 1: build the image, run it on an --internal network, probe via the
    trusted sidecar. None on any missing precondition (caller reports unavailable)."""
    tag = f"aegis-rtp:{run_id}"
    if not build_image(repo_root, tag):
        return None
    app_name = f"aegis-rtp-app-{run_id}"
    with internal_network(f"aegis-rtp-net-{run_id}") as net:
        if net is None:
            return None
        if not start_app(tag, network=net, name=app_name):
            return None
        try:
            if not wait_ready(app_name, port_hint or spec.port or 0, network=net):
                return None
            return run_probe(app_name, spec, network=net, port=(spec.port or port_hint))
        finally:
            stop_app(app_name)


def _serve_and_probe_gvisor(repo_root, recipe, spec, port_hint, *, run_id):
    """Tier 2: serve from a baked base rootfs + repo overlay under runsc in a
    routeless netns, probe on loopback. None on any missing precondition."""
    serve = detect_serve(recipe.dockerfile)
    if serve is None:
        return None
    rootfs = prepare_rootfs(serve.ecosystem, repo_root, run_id)
    if rootfs is None:
        return None
    try:
        return run_gvisor_probe(
            rootfs, serve.cmd, spec, port=(spec.port or port_hint), run_id=run_id,
        )
    finally:
        shutil.rmtree(rootfs, ignore_errors=True)


def make_runtime_probe_tool(repo_root: str) -> Tool:
    """Bind the runtime probe to ``repo_root``. The hunter calls this to serve the
    target app and observe how it actually responds when a verdict hinges on a
    runtime fact it cannot settle statically."""

    def handler(args: dict) -> str:
        try:
            recipe = detect_recipe(repo_root)
            if recipe is None:
                return "// runtime_probe unavailable: no runnable app (no Dockerfile/recipe)"
            port_hint = detect_port(recipe)
            spec, notes = _build_spec(args.get("requests"), port_hint)
            if spec is None:
                head = "// runtime_probe: only GET/HEAD/OPTIONS are allowed"
                return "\n".join([head, *notes]) if notes else head

            run_id = uuid.uuid4().hex[:8]
            # Prefer the tier that is actually available on this host: nested
            # container first, standalone gVisor where nested podman cannot run.
            if runtime_available():
                results = _serve_and_probe_container(repo_root, spec, port_hint, run_id=run_id)
            elif runsc_available():
                results = _serve_and_probe_gvisor(repo_root, recipe, spec, port_hint, run_id=run_id)
            else:
                return "// runtime_probe unavailable: no container runtime"

            if not results:
                return "// runtime_probe unavailable: app did not serve"
            body = _format(results)
            return "\n".join([*notes, body]) if notes else body
        except Exception:  # noqa: BLE001 -- tools never raise; report and move on
            logger.warning("[runtime_probe] errored, reporting unavailable", exc_info=True)
            return "// runtime_probe unavailable: app did not serve"

    return Tool(
        name="runtime_probe",
        description=(
            "Serve the target app in a sandbox and observe how it responds to your "
            "requests. Use ONLY when the verdict genuinely hinges on runtime behavior "
            "you cannot settle from the code (does a route respond without auth, does "
            "an input reflect). This runs the untrusted app and is HEAVY: batch EVERY "
            "path you want to check into a SINGLE call. Observation verbs only "
            "(GET/HEAD/OPTIONS). Returns one line per request: "
            "'GET /path -> HTTP <status> :: <body>'."
        ),
        parameters={
            "type": "object",
            "properties": {
                "requests": {
                    "type": "array",
                    "description": "All the paths to check, batched into this one call.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Request path, e.g. /admin."},
                            "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS"]},
                        },
                        "required": ["path"],
                    },
                },
            },
            "required": ["requests"],
        },
        handler=handler,
    )
