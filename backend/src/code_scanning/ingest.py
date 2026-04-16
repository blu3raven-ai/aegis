"""SAST finding ingestion — parse SARIF/JSONL output from Opengrep scanner."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_TEMP_PREFIX_RE = re.compile(r"^/tmp/tmp\.[^/]+/")


def _strip_temp_prefix(path: str) -> str:
    """Strip Docker container temp-dir prefix from scanner file paths."""
    return _TEMP_PREFIX_RE.sub("", path) or path


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

# ---------------------------------------------------------------------------
# Severity mapping: Opengrep → Portal
# ---------------------------------------------------------------------------

def map_severity(opengrep_severity: str, confidence: str) -> str:
    """Map Opengrep severity + confidence to portal severity.

    | Opengrep | Confidence   | Portal   |
    |----------|-------------|----------|
    | ERROR    | high        | critical |
    | ERROR    | medium/low  | high     |
    | WARNING  | any         | medium   |
    | INFO     | any         | low      |
    """
    sev = opengrep_severity.upper()
    conf = confidence.lower() if confidence else "medium"

    if sev == "ERROR":
        return "critical" if conf == "high" else "high"
    if sev == "WARNING":
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Identity key
# ---------------------------------------------------------------------------

def finding_identity_key(repo: str, file_path: str, rule_id: str, start_line: int) -> str:
    """Build a stable identity key: {repo}:{file_path}:{rule_id}:{start_line}"""
    return f"{repo}:{file_path}:{rule_id}:{start_line}"


def identity_key_from_finding(finding: dict[str, Any]) -> str:
    return finding_identity_key(
        finding.get("repo_full_name", ""),
        finding.get("file_path", ""),
        finding.get("rule_id", ""),
        finding.get("start_line", 0),
    )


# ---------------------------------------------------------------------------
# SARIF/JSONL parsing
# ---------------------------------------------------------------------------

def _parse_sarif_finding(result: dict[str, Any], rule_map: dict[str, dict], repo: str) -> dict[str, Any] | None:
    """Parse a single SARIF result into our finding format."""
    rule_id = result.get("ruleId", "")
    rule_info = rule_map.get(rule_id, {})

    locations = result.get("locations", [])
    if not locations:
        return None
    loc = locations[0]
    phys = loc.get("physicalLocation", {})
    artifact = phys.get("artifactLocation", {})
    region = phys.get("region", {})

    file_path = _strip_temp_prefix(artifact.get("uri", ""))
    start_line = region.get("startLine", 0)
    end_line = region.get("endLine", start_line)

    # Extract severity and confidence from rule metadata
    level = result.get("level", "warning")
    properties = rule_info.get("properties", {})
    confidence = properties.get("confidence", "medium")

    # Map SARIF level to Opengrep severity
    sarif_to_opengrep = {"error": "ERROR", "warning": "WARNING", "note": "INFO", "none": "INFO"}
    opengrep_severity = sarif_to_opengrep.get(level.lower(), "WARNING")
    severity = map_severity(opengrep_severity, confidence)

    # Extract CWE from rule tags
    tags = properties.get("tags") or []
    if not isinstance(tags, list):
        tags = []
    cwe_list = [t for t in tags if isinstance(t, str) and t.startswith("CWE-")]

    # Extract category
    category = properties.get("category", "security")

    # Message
    message = result.get("message", {}).get("text", "")
    rule_name = rule_info.get("shortDescription", {}).get("text", "") or rule_info.get("name", rule_id)

    # Fix suggestion (from SARIF fixes)
    fixes = result.get("fixes", [])
    fix_suggestion = None
    if fixes and isinstance(fixes[0], dict):
        fix_suggestion = fixes[0].get("description", {}).get("text", "") or None

    # Snippet
    snippet = region.get("snippet", {}).get("text", "")

    return {
        "repo_full_name": repo,
        "file_path": file_path,
        "start_line": start_line,
        "end_line": end_line,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "cwe": cwe_list,
        "message": message,
        "snippet": snippet,
        "fix_suggestion": fix_suggestion,
        "state": "open",
        "finding_data": result,
    }


def parse_sarif(sarif_data: dict[str, Any], repo: str) -> list[dict[str, Any]]:
    """Parse a full SARIF document into findings."""
    findings: list[dict[str, Any]] = []
    runs = sarif_data.get("runs", [])
    for run in runs:
        # Build rule lookup
        tool_rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        rule_map = {r.get("id", ""): r for r in tool_rules}

        for result in run.get("results", []):
            finding = _parse_sarif_finding(result, rule_map, repo)
            if finding:
                findings.append(finding)
    return findings


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

    Each line is a JSON object with the finding already in our format
    (the scanner image handles SARIF-to-JSONL conversion).
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
                    finding = {
                        "repo_full_name": raw.get("repo_full_name", raw.get("repository", "")),
                        "file_path": _strip_temp_prefix(raw.get("file_path", raw.get("path", ""))),
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
                        "imports": raw.get("imports") or "",
                        "file_class": raw.get("file_class") or "source",
                        "language": _derive_language(raw.get("file_path", raw.get("path", ""))),
                        "reachability": raw.get("reachability"),
                        "state": "open",
                        "finding_data": raw,
                    }
                    findings.append(finding)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSONL line in %s", findings_path)
    return findings
