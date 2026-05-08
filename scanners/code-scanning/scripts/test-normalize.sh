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
