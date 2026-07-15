"""Opt-in detonation pass: run a repo's setup entry and flag runtime egress.

The end-to-end wiring for the untrusted-skill/setup surface — the defense both the
SkillCloak and DNS-reverse-shell writeups converge on. Static scanning is evadable
because the payload only exists at runtime (packed in a skipped dir, or off-repo in
DNS); this builds the repo, runs its setup entry in the egress-denied sandbox with
the honeypot, and turns any observed egress into a runtime-confirmed finding.

Strictly opt-in (``DETONATE``) — this is the only place we execute a repo's own
setup code end to end. Graceful-skip on ANY missing precondition; never raises,
never a false verdict. A malicious finding is only ever ADDED; static findings are
untouched.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import threading

from runner.sandbox.build import BuildRecipe, build_image_args
from runner.sandbox.detonation import detonate
from runner.sandbox.detonation_verdict import DetonationVerdict, verdict_from_egress
from runner.sandbox.entry import DetonationEntry, detect_entry
from runner.sandbox.harness import container_cli, docker_cli_env, runtime_available
from runner.scanners._subprocess import run_tool

_CHECK_ID = "AGENT_DETONATION_EGRESS"
_GUIDELINE = "A setup/skill entry that phones home at runtime is malicious behavior."
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
    "shell": "FROM debian:stable-slim\nWORKDIR /app\nCOPY . /app\n",
}


def _enabled(get) -> bool:
    return (get("DETONATE") or "").strip().lower() in ("1", "true", "yes", "on")


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
    repo_root: str, *, env, run_id: str, cancel_event: threading.Event | None = None,
) -> list[dict]:
    """Detonate the repo's setup entry, returning any runtime-confirmed findings.
    A no-op (returns []) on every missing precondition — not opted in, no runtime,
    no detectable entry, unsupported ecosystem, build fail, or detonation skip."""
    if not _enabled(env.get) or not runtime_available():
        return []
    entry = detect_entry(repo_root)
    if entry is None:
        return []
    body = dockerfile_body(entry.ecosystem)
    if body is None:
        return []

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
