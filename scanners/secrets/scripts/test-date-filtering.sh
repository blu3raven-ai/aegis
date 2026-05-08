#!/bin/bash
# Tests the git date-filtering logic from run-secrets.sh
# Verifies that --since-commit is set correctly so scans are inclusive of start_date

set -uo pipefail

PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1 — expected: $2  got: $3"; FAIL=$((FAIL + 1)); }

# ── Setup test repo ────────────────────────────────────────────────────────────

TEST_REPO=$(mktemp -d)
trap 'rm -rf "$TEST_REPO"' EXIT

cd "$TEST_REPO"
git init -q
git config user.email "test@example.com"
git config user.name "Test"

make_commit() {
    local date="$1" msg="$2"
    GIT_COMMITTER_DATE="${date}T12:00:00+00:00" \
    GIT_AUTHOR_DATE="${date}T12:00:00+00:00" \
        git commit --allow-empty -m "$msg" -q
}

make_commit "2026-01-01" "jan"
JAN=$(git rev-parse HEAD)

make_commit "2026-02-01" "feb"
FEB=$(git rev-parse HEAD)

make_commit "2026-03-01" "mar"
MAR=$(git rev-parse HEAD)

make_commit "2026-04-01" "apr"
APR=$(git rev-parse HEAD)

# ── Mirror the logic from scan_repository() ───────────────────────────────────
#
# Returns one of:
#   NO_COMMITS          – nothing on/after start_date, skip scan
#   SCAN_ALL            – commits exist but nothing before start_date, scan everything
#   SINCE:<hash>        – pass <hash> as --since-commit (exclusive anchor before start_date)
#
resolve_anchor() {
    local start_date="$1"
    local has_commits anchor

    has_commits=$(git rev-list --after="$start_date" HEAD 2>/dev/null | head -1 || true)
    [[ -z "$has_commits" ]] && { echo "NO_COMMITS"; return; }

    anchor=$(git rev-list --until="$start_date" HEAD 2>/dev/null | head -1 || true)
    [[ -n "$anchor" ]] && echo "SINCE:$anchor" || echo "SCAN_ALL"
}

# ── Tests ──────────────────────────────────────────────────────────────────────

echo "=== Date filtering tests ==="
echo ""

# 1. Date between two commits — anchor is the commit just before start_date
result=$(resolve_anchor "2026-02-15")
expected="SINCE:$FEB"
[[ "$result" == "$expected" ]] \
    && pass "date between commits: anchor is last commit before start_date" \
    || fail "date between commits: anchor is last commit before start_date" "$expected" "$result"

# 2. Date after all commits — nothing to scan
result=$(resolve_anchor "2026-05-01")
[[ "$result" == "NO_COMMITS" ]] \
    && pass "date after all commits: returns NO_COMMITS" \
    || fail "date after all commits: returns NO_COMMITS" "NO_COMMITS" "$result"

# 3. Date before all commits — scan everything
result=$(resolve_anchor "2025-12-01")
[[ "$result" == "SCAN_ALL" ]] \
    && pass "date before all commits: returns SCAN_ALL" \
    || fail "date before all commits: returns SCAN_ALL" "SCAN_ALL" "$result"

# 4. Date exactly on a middle commit — anchor is the commit just before it,
#    so the commit ON the date is included in the scan
result=$(resolve_anchor "2026-02-01")
expected="SINCE:$JAN"
[[ "$result" == "$expected" ]] \
    && pass "date on Feb commit: anchor is Jan commit (Feb is included in scan)" \
    || fail "date on Feb commit: anchor is Jan commit (Feb is included in scan)" "$expected" "$result"

# 5. Date exactly on the first commit — nothing before it, so scan all
result=$(resolve_anchor "2026-01-01")
[[ "$result" == "SCAN_ALL" ]] \
    && pass "date on first commit: returns SCAN_ALL (first commit is included)" \
    || fail "date on first commit: returns SCAN_ALL (first commit is included)" "SCAN_ALL" "$result"

# 6. Date is one day before the last commit — anchor is the Mar commit
result=$(resolve_anchor "2026-03-31")
expected="SINCE:$MAR"
[[ "$result" == "$expected" ]] \
    && pass "date one day before latest commit: anchor is Mar commit" \
    || fail "date one day before latest commit: anchor is Mar commit" "$expected" "$result"

# ── Summary ────────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
