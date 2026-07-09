"""Read the deep-audit findings.jsonl the runner emits (one finding per line)."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MAX_JSONL_SIZE_MB = 50
MAX_JSONL_LINES = 200_000


def read_deep_audit_findings(findings_path: Path) -> list[dict[str, Any]]:
    if not findings_path.exists():
        return []
    if findings_path.stat().st_size > MAX_JSONL_SIZE_MB * 1024 * 1024:
        raise ValueError(f"findings.jsonl too large (> {MAX_JSONL_SIZE_MB}MB)")
    out: list[dict[str, Any]] = []
    with findings_path.open(encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if n > MAX_JSONL_LINES:
                raise ValueError(f"too many lines (> {MAX_JSONL_LINES})")
            s = line.strip()
            if not s:
                continue
            try:
                raw = json.loads(s)
            except json.JSONDecodeError:
                logger.warning("skipping malformed deep-audit JSONL line")
                continue
            if isinstance(raw, dict) and raw.get("check_id"):
                out.append(raw)
    return out
