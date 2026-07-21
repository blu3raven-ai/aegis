"""Opt-in runtime-verification pass: turn "confirmed IF <question>" into proof.

Runs AFTER the static verify pass, over the findings it left at
needs_runtime_verification. For each such finding it builds the target once,
runs it egress-denied on an internal network, probes the app, and rewrites the
verdict to confirmed / ruled_out with runtime_log evidence — or leaves it
untouched. This is the only place Aegis executes untrusted target code, so it is
strictly opt-in (RUNTIME_VERIFY) and graceful-skips on ANY missing precondition:
not opted in, no LLM, no container runtime, no Dockerfile, build fails, no probe
spec, app never ready, or an inconclusive result. It never invents a verdict.
"""
from __future__ import annotations

import logging
import threading
import uuid

from runner.sandbox.build import build_image, detect_recipe
from runner.sandbox.harness import runtime_available, runtime_verify_enabled
from runner.sandbox.network import internal_network
from runner.sandbox.probe import generate_probe
from runner.sandbox.probe_runner import run_probe
from runner.sandbox.runtime_app import detect_port, start_app, stop_app, wait_ready
from runner.sandbox.runtime_verdict import resolve_runtime_verdict

logger = logging.getLogger(__name__)

_RUNTIME_VERDICT = "needs_runtime_verification"


def _runtime_question(finding: dict) -> str:
    meta = finding.get("verification_metadata") or {}
    return (meta.get("runtime_question") or "").strip()


def _targets(findings: list[dict]) -> list[dict]:
    return [
        f for f in findings
        if f.get("verdict") == _RUNTIME_VERDICT and _runtime_question(f)
    ]


def _apply(finding: dict, resolution) -> None:
    finding["verdict"] = resolution.verdict
    evidence = finding.get("evidence")
    if not isinstance(evidence, list):
        evidence = []
    finding["evidence"] = [*evidence, resolution.evidence]
    meta = finding.get("verification_metadata")
    finding["verification_metadata"] = {**(meta if isinstance(meta, dict) else {}),
                                        "runtime_resolution": resolution.reason}


def verify_findings_at_runtime(
    findings: list[dict], repo_root: str, *, env, llm,
    cancel_event: threading.Event | None = None,
) -> list[dict]:
    """Resolve what it can in place and return the same list. A no-op (returns the
    list unchanged) whenever a precondition is missing — never raises, never
    downgrades a finding it couldn't prove."""
    if not runtime_verify_enabled(env.get) or llm is None or not runtime_available():
        return findings
    targets = _targets(findings)
    if not targets:
        return findings
    recipe = detect_recipe(repo_root)
    if recipe is None:
        return findings

    run_id = uuid.uuid4().hex[:8]
    tag = f"aegis-rtv:{run_id}"
    if not build_image(repo_root, tag, cancel_event=cancel_event):
        return findings

    port_hint = detect_port(recipe)
    app_name = f"aegis-rtv-app-{run_id}"
    with internal_network(f"aegis-rtv-net-{run_id}", cancel_event=cancel_event) as net:
        if net is None:
            return findings
        if not start_app(tag, network=net, name=app_name, cancel_event=cancel_event):
            return findings
        try:
            if not wait_ready(app_name, port_hint or 0, network=net, cancel_event=cancel_event):
                return findings
            for finding in targets:
                # Ground the probe in the finding so it targets the real
                # endpoint/code instead of guessing from the one-line question.
                probe_context = {
                    "file": finding.get("file") or finding.get("file_path"),
                    "exploit_chain": finding.get("exploit_chain"),
                    "code_window": finding.get("code_window"),
                }
                spec = generate_probe(
                    _runtime_question(finding), llm=llm, port_hint=port_hint,
                    context=probe_context,
                )
                if spec is None:
                    continue
                results = run_probe(
                    app_name, spec, network=net, port=(spec.port or port_hint),
                    cancel_event=cancel_event,
                )
                resolution = resolve_runtime_verdict(results)
                if resolution.verdict != _RUNTIME_VERDICT and resolution.evidence is not None:
                    _apply(finding, resolution)
        finally:
            stop_app(app_name)
    return findings
