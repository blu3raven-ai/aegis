#!/bin/bash
set -euo pipefail

ORG="$1"
TARGET_DIR="$2"
RUN_ID="$3"

RAW_DIR="$TARGET_DIR"
NORMALIZED_DIR="$TARGET_DIR/runs/$RUN_ID/normalized"
mkdir -p "$NORMALIZED_DIR"

FINDINGS_FILE="$NORMALIZED_DIR/findings.jsonl"
REPOS_FILE="$NORMALIZED_DIR/repositories.json"
SUMMARY_FILE="$NORMALIZED_DIR/summary.json"

> "$FINDINGS_FILE"
echo "[]" > "$REPOS_FILE"
echo "{}" > "$SUMMARY_FILE"

# ── Normalize git findings (from Grype) ──────────────────────────────────────
find "$RAW_DIR" \( -name grype.json -o -name findings.json \) 2>/dev/null | while read -r file; do
    repo_dir=$(dirname "$file")
    repo=$(basename "$repo_dir")
    commit="HEAD"
    if [[ -f "$repo_dir/head-sha.txt" ]]; then
        commit=$(cat "$repo_dir/head-sha.txt" | tr -d '[:space:]')
    fi
    jq -c --arg org "$ORG" --arg repo "$repo" --arg commit "$commit" '
      .matches[]? | {
        organization: $org,
        repository: $repo,
        source: "git",
        commitSha: $commit,
        packageName: (.artifact.name // ""),
        packageVersion: (.artifact.version // ""),
        manifestPath: ((.artifact.locations // []) | if length > 0 then .[0].path // "" else "" end),
        ecosystem: (.artifact.type // ""),
        advisoryId: (.vulnerability.id // ""),
        advisoryAliases: (.vulnerability.aliases // []),
        severity: ((.vulnerability.severity // "unknown") | ascii_downcase),
        cvssScore: ((.vulnerability.cvss // [] | map(.metrics.baseScore // 0) | max) // null),
        fixedVersion: ((.vulnerability.fix.versions // []) | if length > 0 then .[0] else null end),
        fixState: (.vulnerability.fix.state // "unknown"),
        summary: (.vulnerability.description // ""),
        description: (.vulnerability.description // ""),
        references: (.vulnerability.dataSource // "" | if . == "" then [] else [{url: .}] end),
        scanner: "grype",
        stateCandidate: "open"
      }' "$file" >> "$FINDINGS_FILE" 2>/dev/null || true
done

# ── Enrich findings with manifest snippets ────────────────────────────────────
# Build a JSON lookup: { "repo|manifestPath|packageName": { snippet, matchLine } }
CONTEXT_LINES=7
SNIPPET_LOOKUP="$NORMALIZED_DIR/snippet-lookup.json"

# Extract unique (repo, manifestPath, packageName) triples from findings
jq -r '[.repository, .manifestPath, .packageName] | @tsv' "$FINDINGS_FILE" | sort -u | while IFS=$'\t' read -r repo mpath pkg; do
    [[ -z "$mpath" || -z "$repo" ]] && continue
    safe_name=$(echo "$mpath" | sed 's|/|__|g')
    manifest_file=$(find "$RAW_DIR" -path "*/$repo/manifests/$safe_name" -type f 2>/dev/null | head -1)
    [[ -z "$manifest_file" || ! -f "$manifest_file" ]] && continue
    [[ -z "$pkg" ]] && continue

    match_line=$(grep -n -i -m 1 "$pkg" "$manifest_file" 2>/dev/null | head -1 | cut -d: -f1 || true)
    if [[ -n "$match_line" ]]; then
        start=$((match_line - CONTEXT_LINES))
        [[ $start -lt 1 ]] && start=1
        end=$((match_line + CONTEXT_LINES))
        snippet=$(sed -n "${start},${end}p" "$manifest_file" 2>/dev/null | tr '\0' ' ' || true)
    else
        snippet=$(head -15 "$manifest_file" 2>/dev/null | tr '\0' ' ' || true)
        match_line=0
    fi

    [[ -z "$snippet" ]] && continue
    # Emit a JSON line for the lookup
    jq -nc --arg key "${repo}|${mpath}|${pkg}" --arg snippet "$snippet" --argjson ml "${match_line:-0}" \
        '{($key): {s: $snippet, l: $ml}}'
done | jq -sc 'add // {}' > "$SNIPPET_LOOKUP"

# Merge snippets into findings in a single jq pass
jq -c --slurpfile lookup "$SNIPPET_LOOKUP" '
  . as $f |
  ($f.repository + "|" + $f.manifestPath + "|" + $f.packageName) as $key |
  ($lookup[0][$key] // null) as $m |
  if $m then $f + {manifestSnippet: $m.s, manifestMatchLine: $m.l}
  else $f + {manifestSnippet: null, manifestMatchLine: null}
  end
' "$FINDINGS_FILE" > "$NORMALIZED_DIR/findings-enriched.jsonl"

mv "$NORMALIZED_DIR/findings-enriched.jsonl" "$FINDINGS_FILE"
rm -f "$SNIPPET_LOOKUP"

repo_count=$(find "$RAW_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
finding_count=$(wc -l < "$FINDINGS_FILE" | tr -d ' ')

jq -n \
  --arg org "$ORG" \
  --arg runId "$RUN_ID" \
  --argjson repositoryCount "$repo_count" \
  --argjson findingCount "$finding_count" \
  '{organization: $org, runId: $runId, repositoryCount: $repositoryCount, findingCount: $findingCount}' > "$SUMMARY_FILE"

LIFECYCLE_FILE="$NORMALIZED_DIR/findings-lifecycle.jsonl"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -x "$SCRIPT_DIR/lifecycle-dependencies.sh" ]]; then
  bash "$SCRIPT_DIR/lifecycle-dependencies.sh" "$FINDINGS_FILE" "$LIFECYCLE_FILE"
fi
