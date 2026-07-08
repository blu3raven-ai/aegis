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

# Fixed-width tail so a secret's true length is never revealed by the mask.
_MASK = "••••••••"


def _mask_value(value: str) -> str:
    """Mask a secret to a short identifying prefix plus a fixed tail.

    Shows enough leading characters for an analyst to correlate the secret with
    their own vault (and recognise the token type, e.g. ``ghp_``), but never
    enough to use it: at most 4 characters, and never more than a third of the
    value. Short secrets reveal proportionally less; a 2-char value shows
    nothing but the mask.
    """
    keep = min(4, len(value) // 3)
    return value[:keep] + _MASK if keep else _MASK


def _safe_display(value: str, raws: list[str], redacted: str) -> str:
    """Safe display form for one detected secret value.

    Prefer TruffleHog's own ``Redacted`` when it is genuinely a partial — present,
    strictly shorter than the value, and containing no full raw value (some
    detectors set ``Redacted`` to the raw secret itself). Otherwise fall back to
    our deterministic prefix mask. Either way the result never contains the full
    secret.
    """
    if redacted and len(redacted) < len(value) and all(rv not in redacted for rv in raws):
        return redacted
    return _mask_value(value)


def _replacements_for(findings: list[dict[str, Any]]) -> dict[str, str]:
    """Map each raw secret value to its safe display form (see ``_safe_display``)."""
    repl: dict[str, str] = {}
    for f in findings:
        raws = [v for v in (f.get("Raw"), f.get("RawV2")) if v]
        redacted = (f.get("Redacted") or "").strip()
        for v in raws:
            repl[v] = _safe_display(v, raws, redacted)
    return repl


def _redactor(replacements: dict[str, str]) -> Callable[[str], str]:
    """Build a redactor that replaces every detected secret value with its safe
    display form.

    Longest-first so a value that is a substring of another never leaves a
    fragment behind — the full secret never survives into a stored window.
    """
    ordered = sorted((v for v in replacements if v), key=len, reverse=True)

    def _redact(text: str) -> str:
        for value in ordered:
            text = text.replace(value, replacements[value])
        return text

    return _redact


def normalize_file(file_path: Path, source: str, repo_name: str) -> list[dict[str, Any]]:
    """Parse a single per-repo output file into a list of tagged findings."""
    findings: list[dict[str, Any]] = []
    text = file_path.read_text(errors="replace")

    # Repo web URL sidecar written by the scanner beside this output file, so
    # findings can deep-link back to source (empty when the scan didn't write it).
    html_url_file = file_path.parent / "html_url.txt"
    html_url = html_url_file.read_text().strip() if html_url_file.exists() else ""

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
            if html_url:
                finding["repo_html_url"] = html_url
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

    redact = _redactor(_replacements_for(findings))
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
