#!/usr/bin/env bash
# Run the v0.3 benchmark across 3 repo sizes (small / medium / large).
#
# Required env:
#   AEGIS_URL       — e.g. http://localhost:8000
#   AEGIS_API_KEY   — a scan:trigger-scoped API key
#
# Required positional args:
#   $1 small_repo  e.g. acme/tiny-flask
#   $2 small_pr    PR number on small_repo for diff-scoped mode
#   $3 medium_repo
#   $4 medium_pr
#   $5 large_repo
#   $6 large_pr
#
# Required commit SHAs (one for each repo's HEAD at scan time):
#   $7 $8 $9       — small / medium / large HEAD SHAs
set -euo pipefail

if [[ -z "${AEGIS_URL:-}" || -z "${AEGIS_API_KEY:-}" ]]; then
  echo "AEGIS_URL and AEGIS_API_KEY must be set" >&2
  exit 1
fi

if [[ $# -lt 9 ]]; then
  echo "usage: $0 <small_repo> <small_pr> <medium_repo> <medium_pr> <large_repo> <large_pr> <small_sha> <medium_sha> <large_sha>" >&2
  exit 1
fi

SMALL_REPO="$1"  SMALL_PR="$2"
MEDIUM_REPO="$3" MEDIUM_PR="$4"
LARGE_REPO="$5"  LARGE_PR="$6"
SMALL_SHA="$7"   MEDIUM_SHA="$8"   LARGE_SHA="$9"

OUT_DIR=".claude/tmp/v0.3-benchmarks"
mkdir -p "$OUT_DIR"

run_one() {
  local label="$1" repo="$2" sha="$3" pr_arg="$4" out="$5"
  echo "=== running $label ==="
  python backend/tests/scripts/benchmark_ci_scan.py \
    --aegis-url "$AEGIS_URL" \
    --api-key "$AEGIS_API_KEY" \
    --source-id "$repo" \
    --commit-sha "$sha" \
    $pr_arg \
    --output "$out"
}

# Diff-scoped runs (with --pr-number)
run_one "small-diff"   "$SMALL_REPO"  "$SMALL_SHA"  "--pr-number $SMALL_PR"   "$OUT_DIR/small-diff.json"
run_one "medium-diff"  "$MEDIUM_REPO" "$MEDIUM_SHA" "--pr-number $MEDIUM_PR"  "$OUT_DIR/medium-diff.json"
run_one "large-diff"   "$LARGE_REPO"  "$LARGE_SHA"  "--pr-number $LARGE_PR"   "$OUT_DIR/large-diff.json"

# Full-tree baseline runs (no --pr-number)
run_one "small-full"   "$SMALL_REPO"  "$SMALL_SHA"  ""  "$OUT_DIR/small-full.json"
run_one "medium-full"  "$MEDIUM_REPO" "$MEDIUM_SHA" ""  "$OUT_DIR/medium-full.json"
run_one "large-full"   "$LARGE_REPO"  "$LARGE_SHA"  ""  "$OUT_DIR/large-full.json"

echo "all runs complete. JSON results in $OUT_DIR/"
