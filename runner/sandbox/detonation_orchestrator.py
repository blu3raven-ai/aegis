"""Opt-in detonation pass: run a repo's setup entry and flag runtime egress.

The end-to-end wiring for the untrusted-skill/setup surface — the defense both the
malicious-skill cloaking and DNS-reverse-shell writeups converge on. Static scanning is evadable
because the payload only exists at runtime (packed in a skipped dir, or off-repo in
DNS); this builds the repo, runs its setup entry in the egress-denied sandbox with
the honeypot, and turns any observed egress into a runtime-confirmed finding.

Triage-gated: a fast static classifier decides whether a target is worth
detonating (see ``triage.py``), so we run untrusted code selectively, not for
every repo. Executing that code is still strictly opt-in (``DETONATE``) — the only
place we run a repo's own setup end to end. When detonation is OFF but a target
triages as risky, we emit a low-severity 'recommend detonation' finding instead of
running anything, so operators see the signal without us executing code. Graceful-
skip on ANY missing precondition; never raises, never a false verdict; only ever
ADDs a finding — static findings are untouched.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import threading
from collections.abc import Callable

from runner.sandbox.build import BuildRecipe, build_image_args
from runner.sandbox.detonation import detonate
from runner.sandbox.detonation_verdict import DetonationVerdict, verdict_from_egress
from runner.sandbox.entry import DetonationEntry, detect_entry
from runner.sandbox.harness import container_cli, docker_cli_env, runtime_available
from runner.sandbox.triage import TriageResult, triage_target
from runner.scanners._subprocess import run_tool
from runner.scanners.agent.skill_bundle import _OBFUSCATED_EXEC

_CHECK_ID = "AGENT_DETONATION_EGRESS"
_GUIDELINE = "A setup/skill entry that phones home at runtime is malicious behavior."
_RECOMMEND_ID = "AGENT_DETONATION_RECOMMENDED"
_RECOMMEND_GUIDELINE = "This target's setup runs untrusted code and looks risky — detonate it to confirm."
_BUILD_TIMEOUT_S = 600.0

# Per-ecosystem detonation image. COPY . includes .git/ and oversize files on
# purpose — that is exactly where packing hides the payload, so we want it present
# to detonate. Deps install with scripts OFF, so the malicious script does not fire
# during the (networked) build — only during the egress-denied detonation.
_DOCKERFILES = {
    "npm": (
        "FROM node:20-slim\nWORKDIR /app\nCOPY . /app\n"
        "RUN npm install --ignore-scripts --no-audit --no-fund || true\n"
    ),
    # debian-slim carries make + sh; used for both setup scripts and Makefiles.
    "shell": "FROM debian:stable-slim\nWORKDIR /app\nRUN apt-get update && apt-get install -y --no-install-recommends make || true\nCOPY . /app\n",
    "python": "FROM python:3.12-slim\nWORKDIR /app\nCOPY . /app\n",
}


def _enabled(get) -> bool:
    # One sandbox switch: RUNTIME_VERIFY turns on the whole runtime pass (probe +
    # detonate). DETONATE kept as a back-compat alias.
    on = ("1", "true", "yes", "on")
    return (get("RUNTIME_VERIFY") or get("DETONATE") or "").strip().lower() in on


def dockerfile_body(ecosystem: str) -> str | None:
    """The synthesized detonation Dockerfile for an ecosystem, or None if we don't
    know how to build it (→ skip)."""
    return _DOCKERFILES.get(ecosystem)


def _finding(entry: DetonationEntry, verdict: DetonationVerdict) -> dict:
    file = entry.source.split(":", 1)[0]
    fp = hashlib.sha1(f"agent:{_CHECK_ID}:{entry.source}".encode()).hexdigest()[:16]
    return {
        "check_id": _CHECK_ID,
        "title": f"Setup entry {entry.source} attempted egress at runtime",
        "severity": "critical",
        "file": file,
        "line": 0,
        "resource": _CHECK_ID,
        "guideline": _GUIDELINE,
        "fingerprint": fp,
        "verdict": "confirmed",  # we observed the behavior — not a hypothesis
        "evidence": {"summary": verdict.summary, "runtime_log": verdict.evidence},
    }


def _recommend_finding(triage: TriageResult) -> dict:
    """A low-severity, verdict-less finding surfaced when detonation is OFF but the
    target looks worth detonating — so operators see the signal without us running
    any untrusted code."""
    reasons = "; ".join(s.detail for s in triage.risk_signals)
    fp = hashlib.sha1(f"agent:{_RECOMMEND_ID}:{reasons}".encode()).hexdigest()[:16]
    return {
        "check_id": _RECOMMEND_ID,
        "title": "Setup entry warrants runtime detonation",
        "severity": "low",
        "file": "",
        "line": 0,
        "resource": _RECOMMEND_ID,
        "guideline": _RECOMMEND_GUIDELINE,
        "fingerprint": fp,
        "verdict": None,  # a recommendation, not a runtime verdict
        "evidence": {
            "summary": triage.summary,
            "signals": [{"kind": s.kind, "detail": s.detail} for s in triage.risk_signals],
        },
    }


def _build(recipe: BuildRecipe, tag: str, cancel_event: threading.Event | None) -> bool:
    try:
        code, _out, _err = run_tool(
            build_image_args(recipe, tag), timeout=_BUILD_TIMEOUT_S,
            env=docker_cli_env(), cancel_event=cancel_event,
        )
    except Exception:  # noqa: BLE001
        return False
    return code == 0


def detonate_repo(
    repo_root: str, *, env, run_id: str, static_hits: int = 0,
    cancel_event: threading.Event | None = None,
    on_detonation_start: "Callable[[], None] | None" = None,
) -> list[dict]:
    """Triage the target, then act on the verdict:

    - not worth detonating (no entry, or benign) → [] (never runs code, never nags)
    - worth detonating + DETONATE off → a 'recommend detonation' finding (the signal
      without executing anything)
    - worth detonating + DETONATE on → detonate that target and return the runtime
      verdict.
    """
    entry = detect_entry(repo_root)
    obfuscated = bool(entry and entry.body and _OBFUSCATED_EXEC.search(entry.body))
    triage = triage_target(
        repo_root, has_entry=entry is not None,
        entry_obfuscated=obfuscated, static_hits=static_hits,
    )
    if not triage.worth_detonating:
        return []
    if not _enabled(env.get):
        return [_recommend_finding(triage)]
    if not runtime_available():
        return []
    # worth_detonating guarantees a runnable entry.
    body = dockerfile_body(entry.ecosystem)
    if body is None:
        return []

    # Past every triage/consent/runtime gate — real execution (build + run) starts
    # now and can take minutes. Signal it so the progress UI isn't silent here.
    if on_detonation_start is not None:
        on_detonation_start()

    tag = f"aegis-deto-{run_id}:latest"
    fd, path = tempfile.mkstemp(prefix="aegis-deto-", suffix=".Dockerfile")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(body)
        if not _build(BuildRecipe(dockerfile=path, context=repo_root), tag, cancel_event):
            return []
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    events = detonate(tag, entry.cmd, run_id=run_id, cancel_event=cancel_event)
    if events is None:  # setup failure inside detonate → skip
        return []
    verdict = verdict_from_egress(events, entry_source=entry.source)
    return [_finding(entry, verdict)] if verdict.malicious else []
