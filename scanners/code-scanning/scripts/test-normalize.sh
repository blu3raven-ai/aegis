#!/bin/bash
# Run from scanner root: bash scripts/test-normalize.sh
set -euo pipefail

NORMALIZE=./scripts/normalize-code-scanning.sh

if [[ ! -x "$NORMALIZE" ]]; then
  echo "[FAIL] $NORMALIZE missing or not executable"
  exit 1
fi

grep -q "findings.jsonl" "$NORMALIZE"
echo "[PASS] normalize-code-scanning.sh writes findings.jsonl"

grep -q "opengrep.json" "$NORMALIZE"
echo "[PASS] normalize-code-scanning.sh reads opengrep output"

grep -q "stateCandidate" "$NORMALIZE"
echo "[PASS] normalize-code-scanning.sh sets stateCandidate field"

grep -q "file_class" "$NORMALIZE"
echo "[PASS] normalize-code-scanning.sh outputs file_class field"

grep -q "code_flows" "$NORMALIZE"
echo "[PASS] normalize-code-scanning.sh outputs code_flows field"

grep -q "slurpfile ctx" "$NORMALIZE"
echo "[PASS] normalize-code-scanning.sh loads context.json"

grep -q 'vendor.*generated' "$NORMALIZE"
echo "[PASS] normalize-code-scanning.sh pre-filters vendor/generated"

# ── Test: reachability field merged into findings.jsonl ────────────────
echo ""
echo "=== Test: reachability merge ==="

REACH_TMPDIR=$(mktemp -d)
trap 'rm -rf "$REACH_TMPDIR"' EXIT

mkdir -p "$REACH_TMPDIR/testrun/repo"
RAW="$REACH_TMPDIR/testrun/repo"

cat > "$RAW/opengrep.json" << 'SARIF'
{
  "runs": [{
    "tool": {"driver": {"rules": [{"id":"test.r","shortDescription":{"text":"Test"},"properties":{"confidence":"high","tags":[]}}]}},
    "results": [{
      "ruleId": "test.r",
      "level": "warning",
      "message": {"text": "test finding"},
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/main.py"}, "region": {"startLine": 5, "endLine": 5, "snippet": {"text": "  foo()"}}}}]
    }]
  }]
}
SARIF

echo '{}' > "$RAW/context.json"
cat > "$RAW/reachability.json" << 'REOF'
{
  "src/main.py:5": {
    "verdict": "reachable",
    "entry_point": "main",
    "call_chain": [
      {"function": "main", "file": "src/main.py", "line": 1},
      {"function": "foo",  "file": "src/main.py", "line": 5}
    ]
  }
}
REOF

SCRIPT_DIR2="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$SCRIPT_DIR2/normalize-code-scanning.sh" "testorg" "$REACH_TMPDIR" "testrun" 2>/dev/null || true

FINDINGS_FILE="$REACH_TMPDIR/runs/testrun/normalized/findings.jsonl"
if [[ ! -f "$FINDINGS_FILE" ]]; then
    echo "✗ FAIL: findings.jsonl not created"
    exit 1
fi

reach_verdict=$(jq -r '.reachability.verdict // "missing"' "$FINDINGS_FILE" 2>/dev/null | head -1)
if [[ "$reach_verdict" == "reachable" ]]; then
    echo "✓ reachability.verdict merged into finding"
else
    echo "✗ FAIL: expected reachable verdict, got '$reach_verdict'"
    exit 1
fi

# ── Test: repo_html_url propagated from html_url.txt ──────────────────
echo ""
echo "=== Test: repo_html_url propagation ==="

HTML_TMPDIR=$(mktemp -d)
trap 'rm -rf "$HTML_TMPDIR"' EXIT

mkdir -p "$HTML_TMPDIR/repo1"
RAW2="$HTML_TMPDIR/repo1"

cat > "$RAW2/opengrep.json" << 'SARIF2'
{
  "runs": [{
    "tool": {"driver": {"rules": [{"id":"test.url","shortDescription":{"text":"URL test"},"properties":{"confidence":"high","tags":[],"category":"security"}}]}},
    "results": [{
      "ruleId": "test.url",
      "level": "warning",
      "message": {"text": "url test finding"},
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}, "region": {"startLine": 10, "endLine": 10, "snippet": {"text": "  bad_call()"}}}}]
    }]
  }]
}
SARIF2

echo 'https://github.com/acme-org/example-repo' > "$RAW2/html_url.txt"
echo 'abc123' > "$RAW2/head-sha.txt"

NORMALIZE_PY2="$(dirname "$SCRIPT_DIR2")/normalize-code-scanning.py"
[[ ! -f "$NORMALIZE_PY2" ]] && NORMALIZE_PY2="$SCRIPT_DIR2/normalize-code-scanning.py"

if [[ ! -f "$NORMALIZE_PY2" ]]; then
    echo "⚠ SKIP: normalize-code-scanning.py not found at $NORMALIZE_PY2"
else
    python3 "$NORMALIZE_PY2" "testorg" "$HTML_TMPDIR" "unused_run_id" 2>/dev/null || true

    PY_FINDINGS="$HTML_TMPDIR/findings.jsonl"
    if [[ ! -f "$PY_FINDINGS" ]]; then
        echo "✗ FAIL: findings.jsonl not created by Python normalizer"
        exit 1
    fi

    html_url_val=$(python3 -c "import json,sys; [print(json.loads(l).get('repo_html_url','')) for l in open('$PY_FINDINGS') if l.strip()]" 2>/dev/null | head -1)
    if [[ "$html_url_val" == "https://github.com/acme-org/example-repo" ]]; then
        echo "✓ repo_html_url read from html_url.txt and written to findings.jsonl"
    else
        echo "✗ FAIL: expected repo_html_url 'https://github.com/acme-org/example-repo', got '$html_url_val'"
        exit 1
    fi

    # Without html_url.txt — field should be absent
    rm "$RAW2/html_url.txt"
    > "$PY_FINDINGS"
    python3 "$NORMALIZE_PY2" "testorg" "$HTML_TMPDIR" "unused_run_id" 2>/dev/null || true
    has_url=$(python3 -c "import json,sys; [print('yes' if json.loads(l).get('repo_html_url') else 'no') for l in open('$PY_FINDINGS') if l.strip()]" 2>/dev/null | head -1)
    if [[ "$has_url" != "yes" ]]; then
        echo "✓ repo_html_url absent when html_url.txt missing"
    else
        echo "✗ FAIL: repo_html_url unexpectedly present without html_url.txt"
        exit 1
    fi
fi
