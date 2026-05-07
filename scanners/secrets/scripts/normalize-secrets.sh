#!/bin/bash
set -euo pipefail

ORG="$1"
TARGET_DIR="$2"
RUN_ID="${3:-}"

FINDINGS_FILE="$TARGET_DIR/findings.jsonl"

echo "[+] Normalizing secret scan results for: $ORG"

if [[ ! -d "$TARGET_DIR" ]] || [[ ! "$(ls -A "$TARGET_DIR" 2>/dev/null)" ]]; then
    echo "[!] No results found, skipping normalization"
    exit 0
fi

> "$FINDINGS_FILE"

# Repo output dirs are two levels deep: $TARGET_DIR/org/repo/
find "$TARGET_DIR" -mindepth 2 -maxdepth 2 -type d 2>/dev/null | while read -r repo_dir; do
    repo_name="$(basename "$(dirname "$repo_dir")")/$(basename "$repo_dir")"

    if [[ -f "$repo_dir/trufflehog.json" ]]; then
        echo "[+] Processing trufflehog results for $repo_name"
        # trufflehog outputs JSONL (one object per line), not a JSON array
        jq -c '. + {"source": "trufflehog", "repository": "'"$repo_name"'"}' \
            "$repo_dir/trufflehog.json" >> "$FINDINGS_FILE" 2>/dev/null || true
    fi

    if [[ -f "$repo_dir/betterleaks.json" ]]; then
        echo "[+] Processing betterleaks results for $repo_name"
        jq -c '.[] | . + {"source": "betterleaks", "repository": "'"$repo_name"'"}' \
            "$repo_dir/betterleaks.json" >> "$FINDINGS_FILE" 2>/dev/null || true
    fi
done

finding_count=0
if [[ -f "$FINDINGS_FILE" ]] && [[ -s "$FINDINGS_FILE" ]]; then
    finding_count=$(wc -l < "$FINDINGS_FILE" | tr -d ' ')
    echo "[✓] Normalized $finding_count secret findings → $FINDINGS_FILE"
else
    echo "[!] No findings to normalize"
    rm -f "$FINDINGS_FILE"
fi
