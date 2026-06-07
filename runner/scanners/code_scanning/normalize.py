"""Normalize opengrep SARIF output to a findings JSONL.

Port of scanners/code-scanning/scripts/normalize-code-scanning.py. Walks
``target_dir`` for per-repo ``opengrep.json`` SARIF files and emits a
single ``findings.jsonl`` byte-equivalent to the bash original.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_TEMP_PREFIX_RE = re.compile(r"^/tmp/tmp\.[^/]*/")

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _load_repo_metadata(repo_dir: Path) -> tuple[str, str, dict, dict]:
    """Load shared per-repo metadata for engine normalization loops.

    Returns (commit_sha, html_url, context, reachability) with safe defaults
    when files are absent or malformed.
    """
    commit = "HEAD"
    sha_file = repo_dir / "head-sha.txt"
    if sha_file.exists():
        commit = sha_file.read_text().strip() or "HEAD"

    html_url = ""
    html_url_file = repo_dir / "html_url.txt"
    if html_url_file.exists():
        html_url = html_url_file.read_text().strip()

    context: dict = {}
    ctx_file = repo_dir / "context.json"
    if ctx_file.exists():
        try:
            context = json.loads(ctx_file.read_text())
        except Exception:  # noqa: BLE001
            pass

    reachability: dict = {}
    reach_file = repo_dir / "reachability.json"
    if reach_file.exists():
        try:
            reachability = json.loads(reach_file.read_text())
        except Exception:  # noqa: BLE001
            pass

    return commit, html_url, context, reachability


def normalize_file(
    file_path: Path,
    org: str,
    repo: str,
    commit: str,
    context: dict,
    reachability: dict,
) -> tuple[list[dict[str, Any]], set[str]]:
    """Parse a per-repo SARIF file into a list of normalised findings.

    Returns ``(findings, active_rule_ids)``.
    """
    with open(file_path) as f:
        data = json.load(f)

    findings: list[dict[str, Any]] = []
    file_rules: set[str] = set()
    for run in data.get("runs", []):
        rules = {
            r["id"]: r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        file_rules.update(rules.keys())

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})

            level = (
                rule.get("defaultConfiguration", {}).get("level")
                or result.get("level")
                or "warning"
            )
            precision = rule.get("properties", {}).get("precision", "medium")
            confidence = (
                "high" if precision in ("very-high", "high") else precision
            )

            if level == "error":
                severity = "critical" if confidence == "high" else "high"
            elif level == "warning":
                if confidence == "high":
                    severity = "high"
                elif confidence == "low":
                    severity = "low"
                else:
                    severity = "medium"
            else:
                severity = "low"

            loc = (result.get("locations") or [{}])[0] if result.get("locations") else {}
            phys = loc.get("physicalLocation", {})
            artifact = phys.get("artifactLocation", {})
            region = phys.get("region", {})
            uri = artifact.get("uri", "")
            start_line = region.get("startLine", 0)

            tags = rule.get("properties", {}).get("tags", [])
            cwe = [t for t in tags if isinstance(t, str) and t.startswith("CWE-")]

            stripped_uri = _TEMP_PREFIX_RE.sub("", uri)
            ctx_key = f"{stripped_uri}:{start_line}"
            ctx_entry = context.get(ctx_key, {})
            file_class = ctx_entry.get("file_class", "source")

            if file_class in ("vendor", "generated"):
                continue
            if ".secrets." in rule_id.lower():
                continue

            code_flows: list[dict[str, Any]] = []
            for cf in (result.get("codeFlows") or [])[:1]:
                for tf in (cf.get("threadFlows") or [])[:1]:
                    for li in tf.get("locations", []):
                        pl = li.get("location", {}).get("physicalLocation", {})
                        code_flows.append({
                            "file": pl.get("artifactLocation", {}).get("uri", ""),
                            "line": pl.get("region", {}).get("startLine", 0),
                            "snippet": pl.get("region", {}).get("snippet", {}).get("text", ""),
                        })

            findings.append({
                "repo_full_name": repo,
                "file_path": uri,
                "start_line": start_line,
                "end_line": region.get("endLine", start_line),
                "rule_id": rule_id,
                "rule_name": (
                    rule.get("shortDescription", {}).get("text")
                    or rule.get("name")
                    or rule_id
                ),
                "severity": severity,
                "confidence": confidence,
                "category": rule.get("properties", {}).get("category", "security"),
                "cwe": cwe,
                "message": result.get("message", {}).get("text", ""),
                "snippet": region.get("snippet", {}).get("text", ""),
                "fix_suggestion": (
                    (result.get("fixes") or [{}])[0].get("description", {}).get("text")
                    if result.get("fixes")
                    else rule.get("help", {}).get("text") or None
                ),
                "commit_sha": commit,
                "stateCandidate": "open",
                "code_flows": code_flows if code_flows else None,
                "code_window": ctx_entry.get("code_window"),
                "imports": ctx_entry.get("imports"),
                "file_class": file_class,
                "reachability": reachability.get(ctx_key),
                "engine": "opengrep",
            })

    return findings, file_rules


def _normalize_joern_finding(
    raw: dict[str, Any],
    repo: str,
    commit: str,
    html_url: str,
    context: dict,
    reachability: dict,
) -> dict[str, Any]:
    """Convert one Joern adapter output entry to the Aegis finding shape."""
    file_path = raw.get("file", "")
    start_line = int(raw.get("line", 0) or 0)
    cwe_raw = raw.get("cwe", "")
    cwe_list = [cwe_raw] if cwe_raw else []

    stripped_uri = _TEMP_PREFIX_RE.sub("", file_path)
    ctx_key = f"{stripped_uri}:{start_line}"
    ctx_entry = context.get(ctx_key, {})
    file_class = ctx_entry.get("file_class", "source")

    severity = raw.get("severity", "medium")
    if severity not in _VALID_SEVERITIES:
        severity = "medium"

    return {
        "repo_full_name": repo,
        "file_path": file_path,
        "start_line": start_line,
        "end_line": start_line,
        "rule_id": raw.get("rule_id", ""),
        "rule_name": raw.get("title", "") or raw.get("rule_id", ""),
        "severity": severity,
        "confidence": "high",
        "category": "security",
        "cwe": cwe_list,
        "message": raw.get("title", ""),
        "snippet": "",
        "fix_suggestion": None,
        "commit_sha": commit,
        "stateCandidate": "open",
        "code_flows": None,
        "code_window": ctx_entry.get("code_window"),
        "imports": ctx_entry.get("imports"),
        "file_class": file_class,
        "reachability": reachability.get(ctx_key),
        "engine": "joern",
        "dataflow_trace": raw.get("dataflow_trace", []),
        "repo_html_url": html_url if html_url else None,
    }


def normalize_code_scanning_output(
    org: str,
    target_dir: Path,
    run_id: str = "",
) -> tuple[int, int]:
    """Walk ``target_dir`` and emit ``findings.jsonl`` + ``active_rules.json``.

    Returns ``(total, errors)``. Mirrors the bash CLI surface (org / target /
    run_id) but only the ``target_dir`` is used to locate inputs; ``org`` and
    ``run_id`` are accepted for parity with the bash script.
    """
    target = Path(target_dir)
    raw_dir = target
    legacy_dir = target / "runs" / run_id / "raw"
    if legacy_dir.is_dir() and any(legacy_dir.rglob("opengrep.json")):
        raw_dir = legacy_dir
    findings_file = target / "findings.jsonl"

    total = 0
    errors = 0
    active_rules: set[str] = set()

    with open(findings_file, "w") as out:
        for raw_file in sorted(raw_dir.rglob("opengrep.json")):
            repo_dir = raw_file.parent
            repo = str(repo_dir.relative_to(raw_dir))
            commit, html_url, context, reachability = _load_repo_metadata(repo_dir)

            try:
                findings, file_rules = normalize_file(
                    raw_file, org, repo, commit, context, reachability
                )
                active_rules.update(file_rules)
                for f in findings:
                    if html_url:
                        f["repo_html_url"] = html_url
                    out.write(json.dumps(f, separators=(",", ":")) + "\n")
                    total += 1
            except Exception as e:  # noqa: BLE001
                errors += 1
                logger.warning("[!] Failed: %s - %s", repo, e)

        for joern_file in sorted(raw_dir.rglob("joern_findings.json")):
            repo_dir = joern_file.parent
            repo = str(repo_dir.relative_to(raw_dir))
            commit, html_url, context, reachability = _load_repo_metadata(repo_dir)

            try:
                payload = json.loads(joern_file.read_text())
            except Exception as e:  # noqa: BLE001
                errors += 1
                logger.warning("[!] Failed joern normalize: %s - %s", repo, e)
                continue

            for raw in payload.get("findings", []):
                try:
                    f = _normalize_joern_finding(
                        raw, repo, commit, html_url, context, reachability
                    )
                except Exception:  # noqa: BLE001
                    logger.warning("[!] Failed joern entry in %s: %r", repo, raw)
                    errors += 1
                    continue
                if f["file_class"] in ("vendor", "generated"):
                    continue
                out.write(json.dumps(f, separators=(",", ":")) + "\n")
                total += 1

    active_rules_file = Path(target_dir) / "active_rules.json"
    active_rules_file.write_text(json.dumps(sorted(active_rules)))

    logger.info(
        "[+] Normalized %d code scanning findings (%d errors) -> %s",
        total,
        errors,
        findings_file,
    )
    return total, errors
