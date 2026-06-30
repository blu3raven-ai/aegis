"""Normalize trufflehog output to a single findings JSONL.

Walks ``target_dir`` for per-repo ``trufflehog.json`` (JSONL) files, tags each
finding with ``source`` + ``repository``, and emits one JSON object per line to
``findings.jsonl``.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from runner.scanners._context import read_code_window
from runner.scanners.secrets.remediation import build_secret_runbook

logger = logging.getLogger(__name__)

_REDACTION = "•••redacted-secret•••"


def _redactor(secret_values: list[str]) -> Callable[[str], str]:
    """Build a redactor that masks every detected secret value in a text blob.

    Longest-first so a value that is a substring of another never leaves a
    fragment behind. Only non-empty values are masked.
    """
    ordered = sorted({v for v in secret_values if v}, key=len, reverse=True)

    def _redact(text: str) -> str:
        for value in ordered:
            text = text.replace(value, _REDACTION)
        return text

    return _redact


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
            except json.JSONDecodeError:
                continue
            finding["source"] = "trufflehog"
            finding["repository"] = repo_name
            # Deterministic, type-aware rotation runbook for every secret —
            # always-on and independent of the optional LLM verifier.
            finding["recommended_fix"] = build_secret_runbook(finding)
            findings.append(finding)
        # The code window is captured earlier by capture_secret_windows (while
        # the clone still exists) and is already on each finding here — see that
        # function for why the read can't happen at normalize time.

    return findings


def _secret_location(finding: dict[str, Any]) -> tuple[str, int]:
    """File path + 1-based line of a secret finding, across filesystem and
    git source modes (history scans report the location under ``.Git`` rather
    than ``.Filesystem``)."""
    data = (finding.get("SourceMetadata") or {}).get("Data") or {}
    meta = data.get("Filesystem") or data.get("Git") or {}
    return (meta.get("file") or ""), max(1, int(meta.get("line") or 1))


def capture_secret_windows(output_path: Path, clone_dir: Path) -> None:
    """Read each finding's redacted code window from the clone and persist it
    into the scanner output file (JSONL) in place — BEFORE the clone is deleted.

    Normalization runs after every repo's clone has been removed, so it can no
    longer read source; capturing here (the same point the code scanner writes
    its context sidecar) is the only place the file still exists. The window
    masks every detected secret in the repo so no raw value can leak into
    another finding's context.
    """
    try:
        raw_lines = output_path.read_text(errors="replace").splitlines()
    except OSError:
        return
    findings: list[dict[str, Any]] = []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if not findings:
        return

    redact = _redactor([v for f in findings for v in (f.get("Raw"), f.get("RawV2")) if v])
    for finding in findings:
        src_file, line_no = _secret_location(finding)
        if not src_file:
            continue
        window, window_start = read_code_window(clone_dir, src_file, line_no, redact=redact)
        if window is not None:
            finding["code_window"] = window
            finding["code_window_start_line"] = window_start

    output_path.write_text(
        "\n".join(json.dumps(f, separators=(",", ":")) for f in findings) + "\n"
    )


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
