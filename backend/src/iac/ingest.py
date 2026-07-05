"""Read IaC (checkov) findings.jsonl emitted by the runner.

The runner writes one normalized finding dict per line (check_id, title,
severity, file, line, resource, guideline, fingerprint, repo_full_name, and
optional verification fields). The lifecycle hooks read these keys directly, so
no field remapping is needed here — only safe, size-bounded parsing of untrusted
scanner output.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MAX_JSONL_SIZE_MB = 200
MAX_JSONL_LINES = 1_000_000


def read_iac_findings(findings_path: Path) -> list[dict[str, Any]]:
    if not findings_path.exists():
        logger.warning("No IaC findings.jsonl found at %s", findings_path)
        return []

    if findings_path.stat().st_size > MAX_JSONL_SIZE_MB * 1024 * 1024:
        raise ValueError(
            f"findings.jsonl too large (> {MAX_JSONL_SIZE_MB}MB limit)"
        )

    out: list[dict[str, Any]] = []
    line_count = 0
    with findings_path.open(encoding="utf-8") as fh:
        for line in fh:
            line_count += 1
            if line_count > MAX_JSONL_LINES:
                raise ValueError(f"Too many lines (> {MAX_JSONL_LINES} limit)")
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSONL line in %s", findings_path)
                continue
            if isinstance(raw, dict) and raw.get("check_id"):
                out.append(raw)
    return out
