#!/usr/bin/env python3
"""Normalize trufflehog/betterleaks output to findings JSONL."""
import json
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
logger = logging.getLogger(__name__)
from pathlib import Path


def normalize_file(file_path: Path, source: str, repo_name: str) -> list[dict]:
    findings = []
    text = file_path.read_text(errors="replace")

    if source == "trufflehog":
        # JSONL — one object per line
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
    elif source == "betterleaks":
        # JSON array
        try:
            items = json.loads(text)
            if isinstance(items, list):
                for finding in items:
                    finding["source"] = "betterleaks"
                    finding["repository"] = repo_name
                    findings.append(finding)
        except json.JSONDecodeError:
            pass

    return findings


def main():
    org, target_dir, run_id = sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else ""
    target = Path(target_dir)
    findings_file = target / "findings.jsonl"

    total = 0
    errors = 0

    trufflehog_files = list(target.rglob("trufflehog.json"))
    betterleaks_files = list(target.rglob("betterleaks.json"))
    betterleaks_raw_files = list(target.rglob("betterleaks_raw.json"))
    logger.info("[+] target=%s trufflehog=%d betterleaks=%d betterleaks_raw=%d", target, len(trufflehog_files), len(betterleaks_files), len(betterleaks_raw_files))

    with open(findings_file, "w") as out:
        for filename, source in [("trufflehog.json", "trufflehog"), ("betterleaks.json", "betterleaks")]:
            for raw_file in sorted(target.rglob(filename)):
                repo_name = str(raw_file.parent.relative_to(target))
                try:
                    for f in normalize_file(raw_file, source, repo_name):
                        out.write(json.dumps(f, separators=(",", ":")) + "\n")
                        total += 1
                except Exception as e:
                    errors += 1
                    logger.warning("[!] Failed: %s/%s — %s", repo_name, filename, e)

        # Fallback: read betterleaks_raw.json for repos where classify didn't produce betterleaks.json
        classified_repos = {str(f.parent.relative_to(target)) for f in target.rglob("betterleaks.json")}
        for raw_file in sorted(target.rglob("betterleaks_raw.json")):
            repo_name = str(raw_file.parent.relative_to(target))
            if repo_name in classified_repos:
                continue
            try:
                for f in normalize_file(raw_file, "betterleaks", repo_name):
                    out.write(json.dumps(f, separators=(",", ":")) + "\n")
                    total += 1
            except Exception as e:
                errors += 1
                logger.warning("[!] Failed: %s/betterleaks_raw.json — %s", repo_name, e)

    logger.info("[✓] Normalized %d findings (%d errors) → %s", total, errors, findings_file)


if __name__ == "__main__":
    main()
