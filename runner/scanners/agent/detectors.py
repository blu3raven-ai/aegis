"""Deterministic detectors for AI-agent-targeted malicious content.

``scan_repo`` walks the agent-instruction surface (see targets.py) and runs each
detector over it. Detectors are added phase by phase behind this single
entrypoint; today it runs invisible-unicode smuggling detection.

Each finding dict mirrors the shape the backend lifecycle reads directly
(see backend/src/agent_scanning/lifecycle.py):

    {
        "check_id":  "AGENT_UNICODE_TAGS",   # stable detector rule id
        "title":     "...",
        "severity":  "critical|high|medium|low",
        "file":      "relative/path",
        "line":      12,
        "resource":  "...",                  # stable identity token
        "guideline": "...",
        "fingerprint": "...",
    }
"""
from __future__ import annotations

import logging

from runner.scanners.agent.advisory import enrich
from runner.scanners.agent.autoexec_config import scan_autoexec_configs
from runner.scanners.agent.code_comments import scan_code_comments
from runner.scanners.agent.config_keys import scan_config
from runner.scanners.agent.encoded_payloads import scan_encoded
from runner.scanners.agent.exfil_instruction import scan_exfil
from runner.scanners.agent.homoglyph import scan_homoglyphs
from runner.scanners.agent.injection_markers import scan_injection
from runner.scanners.agent.skill_bundle import scan_skill_bundles
from runner.scanners.agent.targets import iter_target_files
from runner.scanners.agent.unicode_smuggling import scan_text

logger = logging.getLogger(__name__)

# Backstop so a pathological repo can't produce an unbounded findings.jsonl.
_MAX_FINDINGS = 5000

# Each detector takes (rel_path, text) and returns a list of finding dicts.
_DETECTORS = (
    ("unicode", scan_text),
    ("config", scan_config),
    ("injection", scan_injection),
    ("exfil", scan_exfil),
    ("encoded", scan_encoded),
    ("homoglyph", scan_homoglyphs),
)

# Repo-level passes that walk their own (non-instruction) file set.
_REPO_PASSES = (
    ("skill-bundle", scan_skill_bundles),
    ("autoexec", scan_autoexec_configs),
    ("code-comment", scan_code_comments),
)


def _finalize(findings: list[dict]) -> list[dict]:
    """Cap, then attach per-rule advisory text so each finding carries the
    analyst-facing *why it matters* and *what to do* (see advisory.py)."""
    return [enrich(f) for f in findings[:_MAX_FINDINGS]]


def scan_repo(repo_root: str) -> list[dict]:
    """Walk ``repo_root``'s agent-instruction files and return findings."""
    findings: list[dict] = []
    for abs_path, rel_path in iter_target_files(repo_root):
        try:
            text = abs_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            # Binary or unreadable — not agent-loaded instruction content.
            continue
        for name, detector in _DETECTORS:
            try:
                findings.extend(detector(rel_path, text))
            except Exception:  # noqa: BLE001 — one bad file must not sink the scan
                logger.exception("[!] agent %s detector failed for %s", name, rel_path)
        if len(findings) >= _MAX_FINDINGS:
            logger.warning("[!] agent scan hit findings cap (%d)", _MAX_FINDINGS)
            return _finalize(findings)

    # Repo-level passes over non-instruction files (skill scripts, auto-exec
    # config, and source-comment injection/exfil).
    for name, scan_pass in _REPO_PASSES:
        try:
            findings.extend(scan_pass(repo_root))
        except Exception:  # noqa: BLE001
            logger.exception("[!] agent %s pass failed", name)
        if len(findings) >= _MAX_FINDINGS:
            return _finalize(findings)
    return _finalize(findings)
