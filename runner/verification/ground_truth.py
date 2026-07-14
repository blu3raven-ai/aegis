"""One-per-scan advisory recon: sample the files findings landed in and ask the
model for the repo's known-good baseline. Fail-open — any error returns None so
the caller falls back to user-declared carve-outs only and the scan never blocks.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from runner.verification.prompts.sast import (
    GROUND_TRUTH_SYSTEM,
    ground_truth_user_message,
)
from runner.verification.schemas.verdict import GroundTruth

logger = logging.getLogger(__name__)

# Bounded like the IaC sibling excerpt: keep recon cheap and deterministic.
_MAX_FILES = 6
_MAX_BYTES_PER_FILE = 2000


def _sample_files(repo_root: str, findings: list[dict[str, Any]]) -> list[tuple[str, str]]:
    seen: list[str] = []
    for f in findings:
        rel = str(f.get("file") or f.get("file_path") or "")
        if rel and rel not in seen:
            seen.append(rel)
        if len(seen) >= _MAX_FILES:
            break
    out: list[tuple[str, str]] = []
    for rel in seen:
        abs_path = os.path.join(repo_root, rel)
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                out.append((rel, fh.read(_MAX_BYTES_PER_FILE)))
        except OSError:
            continue
    return out


def build_ground_truth(*, repo_root: str, findings: list[dict[str, Any]], llm) -> GroundTruth | None:
    """Run the recon pass once. Returns None on disabled LLM, no sampleable files,
    or any error (fail-open)."""
    if llm is None:
        return None
    samples = _sample_files(repo_root, findings)
    if not samples:
        return None
    try:
        result = llm.chat_json(
            [
                {"role": "system", "content": GROUND_TRUTH_SYSTEM},
                {"role": "user", "content": ground_truth_user_message(samples)},
            ],
            GroundTruth,
            temperature=0.0, max_tokens=600,
        )
    except Exception:  # noqa: BLE001 — advisory half must never break a scan
        logger.warning("[!] ground-truth recon failed; continuing without it", exc_info=True)
        return None
    return result.parsed  # None if schema-invalid → treated as "no ground truth"
