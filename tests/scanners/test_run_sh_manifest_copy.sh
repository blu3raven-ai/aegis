#!/usr/bin/env bash
# Tests for the manifest path-stripping logic in run.sh.
# Simulates the loop that copies manifest files to the manifests/ directory.

set -euo pipefail

PASS=0
FAIL=0

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

# Replicate the path-stripping and copy logic from run.sh.
# Uses python3 for realpath to work on both macOS and Linux.
copy_manifest() {
    local mpath="$1" temp_dir="$2" manifests_dir="$3"
    local clean_mpath="${mpath#/}"
    [[ "$clean_mpath" == *..* ]] && return 0
    local resolved
    resolved=$(python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$temp_dir/$clean_mpath" 2>/dev/null || echo "")
    [[ -z "$resolved" || "$resolved" != "$temp_dir"/* ]] && return 0
    if [ -f "$resolved" ]; then
        local safe_name
        safe_name=$(echo "$clean_mpath" | sed 's|/|__|g')
        cp "$resolved" "$manifests_dir/$safe_name"
    fi
}

run_test() {
    local name="$1" mpath="$2" rel_file="$3" expected_safe="$4"
    local tmp
    tmp=$(mktemp -d)
    # Resolve symlinks so the containment check matches on macOS (/var → /private/var)
    tmp=$(python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$tmp")
    local temp_dir="$tmp/repo" manifests_dir="$tmp/manifests"
    mkdir -p "$temp_dir/$(dirname "$rel_file")" "$manifests_dir"
    echo "content" > "$temp_dir/$rel_file"

    copy_manifest "$mpath" "$temp_dir" "$manifests_dir"

    if [ -f "$manifests_dir/$expected_safe" ]; then
        pass "$name"
    else
        fail "$name — expected $manifests_dir/$expected_safe"
    fi
    rm -rf "$tmp"
}

run_security_test() {
    local name="$1" mpath="$2"
    local tmp
    tmp=$(mktemp -d)
    tmp=$(python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$tmp")
    local temp_dir="$tmp/repo" manifests_dir="$tmp/manifests"
    mkdir -p "$temp_dir" "$manifests_dir"
    copy_manifest "$mpath" "$temp_dir" "$manifests_dir"
    local count
    count=$(find "$manifests_dir" -type f | wc -l)
    if [ "$count" -eq 0 ]; then
        pass "$name"
    else
        fail "$name — traversal not blocked"
    fi
    rm -rf "$tmp"
}

# --- Functional tests ---
run_test "leading slash is stripped (Syft path)" \
    "/requirements.txt" "requirements.txt" "requirements.txt"

run_test "no leading slash still works" \
    "requirements.txt" "requirements.txt" "requirements.txt"

run_test "nested path with leading slash" \
    "/src/requirements.txt" "src/requirements.txt" "src__requirements.txt"

run_test "nested path without leading slash" \
    "src/requirements.txt" "src/requirements.txt" "src__requirements.txt"

run_test "deeply nested path with leading slash" \
    "/a/b/requirements-ml.txt" "a/b/requirements-ml.txt" "a__b__requirements-ml.txt"

# --- Security tests ---
run_security_test "path traversal with .. is blocked" "../escape.txt"
run_security_test "path traversal with leading slash and .. is blocked" "/../escape.txt"
run_security_test "embedded .. is blocked" "src/../../escape.txt"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
