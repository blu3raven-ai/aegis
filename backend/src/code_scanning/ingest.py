"""SAST finding ingestion — read canonical findings.jsonl emitted by the runner."""
from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_TEMP_PREFIX_RE = re.compile(r"^/tmp/tmp\.[^/]+/")
_CHECKOUT_MARKER = "_checkout/"


def _strip_temp_prefix(path: str) -> str:
    """Strip Docker container temp-dir prefix from scanner file paths."""
    return _TEMP_PREFIX_RE.sub("", path) or path


def repo_relative_path(path: str) -> str:
    """Reduce a scanner-emitted path to its repo-relative form.

    semgrep runs against the absolute clone directory, so its reported paths
    carry the container temp-dir prefix *and* the clone's own ``<repo>/_checkout/``
    prefix (e.g. ``/tmp/tmp.x/acme-repo/_checkout/app/db.py``). Both are runner
    scaffolding, not part of the source tree. Stripping them here — at the single
    ingest choke point — keeps the stored ``file_path``, the identity key (which
    embeds it), the detail blob, and view-in-repo links all agreed on the same
    repo-relative path, and matches the runner's own ``resolve_in_root``
    re-anchoring. Re-anchor on the *last* ``_checkout/`` so a repo that legitimately
    contains the segment deeper in its tree still resolves correctly.
    """
    stripped = _strip_temp_prefix(path)
    idx = stripped.rfind(_CHECKOUT_MARKER)
    return stripped[idx + len(_CHECKOUT_MARKER):] if idx != -1 else stripped


MAX_JSONL_SIZE_MB = 200
MAX_JSONL_LINES = 1_000_000
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
VALID_CONFIDENCES = frozenset({"high", "medium", "low"})

_FILE_EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cs": "csharp",
    ".scala": "scala",
    ".kt": "kotlin",
    ".swift": "swift",
    ".sh": "bash",
    ".bash": "bash",
}


def _derive_language(file_path: str) -> str:
    """Derive programming language from file extension."""
    ext = Path(file_path).suffix.lower()
    return _FILE_EXTENSION_TO_LANGUAGE.get(ext, "unknown")


def _snippet_fingerprint(snippet: str) -> str | None:
    """Line-position-independent fingerprint of a matched code snippet.

    Per-line whitespace is normalised so reindentation does not change identity;
    returns None when there is nothing to fingerprint.
    """
    if not snippet or not snippet.strip():
        return None
    normalized = "\n".join(line.strip() for line in snippet.strip().splitlines())
    return hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:12]


def code_finding_identity(
    repo: str, file_path: str, rule_id: str, start_line: int, snippet: str = ""
) -> str:
    """Identity key for a SAST finding: ``{repo}:{file_path}:{rule_id}:{loc}``.

    ``loc`` combines the start line with a content fingerprint of the matched
    snippet (``{line}:h{fp}``). Including the line prevents two textually
    identical vulnerable patterns at different locations in the same file from
    collapsing to a single Finding row. Without a snippet it falls back to the
    raw start line. Colons in the components are escaped so they cannot be
    confused with the separators.
    """
    def _esc(v: str) -> str:
        return str(v).replace(":", "%3A")

    fp = _snippet_fingerprint(snippet)
    loc = f"{start_line or 0}:h{fp}" if fp else str(start_line or 0)
    return f"{_esc(repo)}:{_esc(file_path)}:{_esc(rule_id)}:{loc}"


def finding_identity_key(
    repo: str, file_path: str, rule_id: str, start_line: int, snippet: str = ""
) -> str:
    """Build a SAST finding identity key (see :func:`code_finding_identity`)."""
    return code_finding_identity(repo, file_path, rule_id, start_line, snippet)


def identity_key_from_finding(finding: dict[str, Any]) -> str:
    return code_finding_identity(
        finding.get("repo_full_name", ""),
        finding.get("file_path", ""),
        finding.get("rule_id", ""),
        finding.get("start_line", 0),
        finding.get("snippet", "") or "",
    )


def load_active_rule_ids(findings_path: Path) -> set[str]:
    """Load the set of rule IDs that were active in this scan run.

    Returns an empty set if active_rules.json is absent (older scanner image),
    which causes the lifecycle to fall back to the old behaviour (mark all
    vanished findings as fixed).
    """
    active_rules_path = findings_path.parent / "active_rules.json"
    if not active_rules_path.exists():
        return set()
    try:
        with active_rules_path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return {str(r) for r in data if r}
    except Exception:
        logger.warning("Could not read active_rules.json at %s", active_rules_path)
    return set()


def ingest_findings_jsonl(findings_path: Path) -> list[dict[str, Any]]:
    """Read findings.jsonl and return parsed findings.

    Each line is a JSON object emitted by the runner — either already in
    canonical snake_case form, or in SARIF-style camelCase which this
    function remaps inline below.
    """
    if not findings_path.exists():
        logger.warning("No findings.jsonl found at %s", findings_path)
        return []

    stats = findings_path.stat()
    max_bytes = MAX_JSONL_SIZE_MB * 1024 * 1024
    if stats.st_size > max_bytes:
        raise ValueError(
            f"findings.jsonl too large ({round(stats.st_size / 1024 / 1024)}MB > {MAX_JSONL_SIZE_MB}MB limit)"
        )

    findings: list[dict[str, Any]] = []
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
                if not isinstance(raw, dict):
                    continue

                # If the line contains SARIF-style data (from scanner), map it
                if "ruleId" in raw or "rule_id" in raw:
                    raw_severity = str(raw.get("severity") or "").lower()
                    raw_confidence = str(raw.get("confidence") or "").lower()
                    engine = raw.get("engine")
                    if engine is None:
                        logger.warning(
                            "[code-scanning] finding has no `engine` field; defaulting to 'semgrep'. "
                            "Runner output may be malformed: rule_id=%s file=%s",
                            raw.get("rule_id", raw.get("ruleId", "")),
                            raw.get("file_path", raw.get("path", "")),
                        )
                        engine = "semgrep"
                    file_path = repo_relative_path(raw.get("file_path", raw.get("path", "")))
                    finding = {
                        "repo_full_name": raw.get("repo_full_name", raw.get("repository", "")),
                        "file_path": file_path,
                        "start_line": raw.get("start_line", raw.get("startLine", 0)),
                        "end_line": raw.get("end_line", raw.get("endLine", 0)),
                        "rule_id": raw.get("rule_id", raw.get("ruleId", "")),
                        "rule_name": raw.get("rule_name", raw.get("ruleName", "")),
                        "severity": raw_severity if raw_severity in VALID_SEVERITIES else "medium",
                        "confidence": raw_confidence if raw_confidence in VALID_CONFIDENCES else "medium",
                        "category": raw.get("category", "security"),
                        "cwe": raw.get("cwe", []),
                        "message": raw.get("message", ""),
                        "snippet": raw.get("snippet", ""),
                        "fix_suggestion": raw.get("fix_suggestion", raw.get("fixSuggestion")),
                        "code_flows": raw.get("code_flows") or [],
                        "code_window": raw.get("code_window") or "",
                        "code_window_start_line": raw.get("code_window_start_line"),
                        "imports": raw.get("imports") or "",
                        "file_class": raw.get("file_class") or "source",
                        "language": _derive_language(file_path),
                        "reachability": raw.get("reachability"),
                        "repo_html_url": raw.get("repo_html_url", ""),
                        "engine": engine,
                        "state": "open",
                        # Verification fields the runner stamps after its LLM pass.
                        # These must be promoted to the top level (not left inside
                        # finding_data) or the lifecycle's extract_detail drops them
                        # and the preview-ingested `needs_verify` verdict persists.
                        "verdict": raw.get("verdict"),
                        "evidence": raw.get("evidence"),
                        "exploit_chain": raw.get("exploit_chain"),
                        "verification_metadata": raw.get("verification_metadata"),
                        "recommended_fix": raw.get("recommended_fix"),
                        "finding_data": raw,
                    }
                    findings.append(finding)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSONL line in %s", findings_path)
    return findings
