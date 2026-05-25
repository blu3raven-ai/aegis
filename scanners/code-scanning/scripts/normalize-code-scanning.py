#!/usr/bin/env python3
"""Normalize opengrep SARIF output to findings JSONL."""
import json
import logging
import re
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def normalize_file(file_path: Path, org: str, repo: str, commit: str, context: dict, reachability: dict) -> tuple[list[dict], set[str]]:
    """Returns (findings, active_rule_ids)."""
    with open(file_path) as f:
        data = json.load(f)

    findings = []
    file_rules: set[str] = set()
    for run in data.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        file_rules.update(rules.keys())

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})

            level = rule.get("defaultConfiguration", {}).get("level") or result.get("level") or "warning"
            precision = rule.get("properties", {}).get("precision", "medium")
            confidence = "high" if precision in ("very-high", "high") else precision

            if level == "error":
                severity = "critical" if confidence == "high" else "high"
            elif level == "warning":
                severity = "high" if confidence == "high" else ("low" if confidence == "low" else "medium")
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

            # Strip /tmp/tmp.XXXX/ prefix that Opengrep embeds in SARIF URIs so the
            # lookup key matches what extract-context.sh writes to context.json
            stripped_uri = re.sub(r"^/tmp/tmp\.[^/]*/", "", uri)
            ctx_key = f"{stripped_uri}:{start_line}"
            ctx_entry = context.get(ctx_key, {})
            file_class = ctx_entry.get("file_class", "source")

            if file_class in ("vendor", "generated"):
                continue
            if ".secrets." in rule_id.lower():
                continue

            code_flows = []
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
                "rule_name": rule.get("shortDescription", {}).get("text") or rule.get("name") or rule_id,
                "severity": severity,
                "confidence": confidence,
                "category": rule.get("properties", {}).get("category", "security"),
                "cwe": cwe,
                "message": result.get("message", {}).get("text", ""),
                "snippet": region.get("snippet", {}).get("text", ""),
                "fix_suggestion": (result.get("fixes") or [{}])[0].get("description", {}).get("text") if result.get("fixes") else None,
                "commit_sha": commit,
                "stateCandidate": "open",
                "code_flows": code_flows if code_flows else None,
                "code_window": ctx_entry.get("code_window"),
                "imports": ctx_entry.get("imports"),
                "file_class": file_class,
                "reachability": reachability.get(ctx_key),
            })

    return findings, file_rules


def main():
    org, target_dir, run_id = sys.argv[1], sys.argv[2], sys.argv[3]
    target = Path(target_dir)
    raw_dir = target
    # Legacy path fallback
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
            commit = "HEAD"
            sha_file = repo_dir / "head-sha.txt"
            if sha_file.exists():
                commit = sha_file.read_text().strip() or "HEAD"

            context = {}
            ctx_file = repo_dir / "context.json"
            if ctx_file.exists():
                try:
                    context = json.loads(ctx_file.read_text())
                except Exception:
                    pass

            reachability = {}
            reach_file = repo_dir / "reachability.json"
            if reach_file.exists():
                try:
                    reachability = json.loads(reach_file.read_text())
                except Exception:
                    pass

            try:
                findings, file_rules = normalize_file(raw_file, org, repo, commit, context, reachability)
                active_rules.update(file_rules)
                for f in findings:
                    out.write(json.dumps(f, separators=(",", ":")) + "\n")
                    total += 1
            except Exception as e:
                errors += 1
                logger.warning("[!] Failed: %s — %s", repo, e)

    active_rules_file = Path(target_dir) / "active_rules.json"
    active_rules_file.write_text(json.dumps(sorted(active_rules)))

    logger.info("[✓] Normalized %d code scanning findings (%d errors) → %s", total, errors, findings_file)


if __name__ == "__main__":
    main()
