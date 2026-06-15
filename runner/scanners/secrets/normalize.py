"""Normalize trufflehog output to a single findings JSONL.

Walks ``target_dir`` for per-repo ``trufflehog.json`` (JSONL) files, tags each
finding with ``source`` + ``repository``, and emits one JSON object per line to
``findings.jsonl``.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def normalize_file(file_path: Path, source: str, repo_name: str) -> list[dict[str, Any]]:
    """Parse a single per-repo output file into a list of tagged findings."""
    findings: list[dict[str, Any]] = []
    text = file_path.read_text(errors="replace")

    if source == "trufflehog":
        # JSONL - one object per line
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                finding["source"] = "trufflehog"
                finding["repository"] = repo_name
                findings.append(finding)
            except json.JSONDecodeError:
                continue

    return findings


def normalize_secrets_output(
    org: str,
    target_dir: Path,
    run_id: str = "",
) -> tuple[int, int]:
    """Walk ``target_dir`` and emit ``findings.jsonl``.

    Returns ``(total, errors)``. The ``org`` and ``run_id`` arguments are
    accepted for parity with the bash CLI but are not embedded in the output
    record (matching the original normalize-secrets behaviour, which only
    annotated ``source`` + ``repository``).
    """
    target = Path(target_dir)
    findings_file = target / "findings.jsonl"

    total = 0
    errors = 0

    trufflehog_files = list(target.rglob("trufflehog.json"))
    logger.info("[+] target=%s trufflehog=%d", target, len(trufflehog_files))

    with open(findings_file, "w") as out:
        for raw_file in sorted(target.rglob("trufflehog.json")):
            repo_name = str(raw_file.parent.relative_to(target))
            try:
                for f in normalize_file(raw_file, "trufflehog", repo_name):
                    out.write(json.dumps(f, separators=(",", ":")) + "\n")
                    total += 1
            except Exception as e:  # noqa: BLE001
                errors += 1
                logger.warning(
                    "[!] Failed: %s/trufflehog.json - %s", repo_name, e
                )

    logger.info(
        "[OK] Normalized %d findings (%d errors) -> %s", total, errors, findings_file
    )
    return total, errors
