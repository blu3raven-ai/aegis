#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source /scanner/shared/lib.sh
setup_output_dir

GIT_REPOS="${GIT_REPOS:-}"
GIT_TOKEN="${GIT_TOKEN:-}"
RULESETS="${RULESETS:-}"

check_dependencies git opengrep jq

scan_repository() {
    local repo_url="$1"
    local target_dir="$2"

    local repo_name
    repo_name=$(repo_name_from_url "$repo_url")
    log_scanning "$repo_name"

    local temp_dir
    temp_dir=$(mktemp -d)
    local original_dir
    original_dir=$(pwd)

    # GIT_ASKPASS keeps the token off the process list and .git/config
    local askpass=""
    if [[ -n "${GIT_TOKEN:-}" ]]; then
        askpass=$(mktemp)
        cat > "$askpass" << 'ASKPASS'
#!/bin/bash
echo "$GIT_TOKEN"
ASKPASS
        chmod 700 "$askpass"
    fi

    trap 'cd "$original_dir"; rm -rf "$temp_dir" ${askpass:+"$askpass"}' RETURN

    local clone_env=()
    if [[ -n "$askpass" ]]; then
        clone_env=(env "GIT_ASKPASS=$askpass")
    fi

    if ! "${clone_env[@]}" git clone --depth 1 "$repo_url" "$temp_dir" >/dev/null 2>&1; then
        echo "[!] Failed to clone $repo_name"
        rm -rf "$temp_dir"
        return 0
    fi

    cd "$temp_dir"

    local head_sha
    head_sha=$(git rev-parse HEAD 2>/dev/null || echo "HEAD")

    local repo_output_dir="$target_dir/$repo_name"
    mkdir -p "$repo_output_dir"

    echo "$head_sha" > "$repo_output_dir/head-sha.txt"

    # Named rulesets use bundled rules; absolute paths pass through directly
    local config_args=()
    local use_bundled=false

    if [[ -z "${RULESETS:-}" ]]; then
        use_bundled=true
    else
        local custom_args=()
        IFS=',' read -ra ruleset_list <<< "$RULESETS"
        for r in "${ruleset_list[@]}"; do
            r="${r//[[:space:]]/}"
            [[ -z "$r" ]] && continue
            if [[ "$r" == /* && -e "$r" ]]; then
                custom_args+=("--config" "$r")
            else
                use_bundled=true
            fi
        done
        config_args+=("${custom_args[@]}")
    fi

    if [[ "$use_bundled" == true || ${#config_args[@]} -eq 0 ]]; then
        config_args+=("--config" "/scanner/rules")
    fi

    # Exit 1 = findings found (not an error)
    local rc=0
    local stderr_file
    stderr_file=$(mktemp)
    opengrep scan \
        "${config_args[@]}" \
        --sarif \
        --dataflow-traces \
        -o "$repo_output_dir/opengrep.json" \
        --jobs 4 \
        --no-git-ignore \
        "$temp_dir" 2>"$stderr_file" || rc=$?

    if [[ $rc -gt 1 ]]; then
        local err_snippet
        err_snippet=$(tail -5 "$stderr_file" 2>/dev/null | head -c 500)
        echo "[!] Opengrep exited with code $rc for $repo_name: $err_snippet"
    fi
    rm -f "$stderr_file"

    if [[ ! -s "$repo_output_dir/opengrep.json" ]]; then
        rm -f "$repo_output_dir/opengrep.json"
    fi

    # Extract code context + reachability when findings exist
    if [[ -s "$repo_output_dir/opengrep.json" ]]; then
        local extract_script=""
        if [[ -x "$SCRIPT_DIR/scripts/extract-context.sh" ]]; then
            extract_script="$SCRIPT_DIR/scripts/extract-context.sh"
        elif [[ -x "$SCRIPT_DIR/extract-context.sh" ]]; then
            extract_script="$SCRIPT_DIR/extract-context.sh"
        fi
        if [[ -n "$extract_script" ]]; then
            "$extract_script" "$temp_dir" "$repo_output_dir" 2>/dev/null || true
        fi

        local reach_script=""
        if [[ -x "$SCRIPT_DIR/scripts/run-reachability.sh" ]]; then
            reach_script="$SCRIPT_DIR/scripts/run-reachability.sh"
        elif [[ -x "$SCRIPT_DIR/run-reachability.sh" ]]; then
            reach_script="$SCRIPT_DIR/run-reachability.sh"
        fi
        if [[ -n "$reach_script" ]]; then
            "$reach_script" "$temp_dir" "$repo_output_dir" 2>/dev/null || true
        fi
    fi

    cd "$original_dir"

    for f in "$repo_output_dir"/*.json; do
        [ -f "$f" ] && register_output "$f" "$repo_name"
    done

    log_finished "$repo_name"
}

# Exports for parallel execution
export -f scan_repository repo_name_from_url log_scanning log_finished register_output
[[ -n "${GIT_TOKEN:-}" ]] && export GIT_TOKEN
export SCRIPT_DIR RUN_ID RULESETS

# Main execution
ORG_LABEL="${ORG_LABEL:-default}"
TARGET_DIR="$OUTDIR"
mkdir -p "$TARGET_DIR"

if [[ -z "$GIT_REPOS" ]]; then
    echo "[!] No GIT_REPOS specified — nothing to scan"
    exit 0
fi

REPO_LIST=$(parse_repos "$GIT_REPOS")
REPO_COUNT=$(echo "$REPO_LIST" | wc -l | tr -d ' ')
echo "[+] $REPO_COUNT repositories to scan"

PARALLEL_SCRIPT=$(mktemp /tmp/parallel_scan.XXXXXX.sh)
cat > "$PARALLEL_SCRIPT" << 'EOF'
#!/bin/bash
repo_url="$1"
target_dir="$2"
scan_repository "$repo_url" "$target_dir"
exit 0
EOF
chmod 700 "$PARALLEL_SCRIPT"

if command -v parallel >/dev/null 2>&1; then
    echo "$REPO_LIST" | parallel -j "$CONCURRENCY" "$PARALLEL_SCRIPT" "{}" "$TARGET_DIR" || true
else
    echo "$REPO_LIST" | xargs -I {} -P "$CONCURRENCY" "$PARALLEL_SCRIPT" "{}" "$TARGET_DIR" || true
fi

rm -f "$PARALLEL_SCRIPT"

# Normalization
NORMALIZE_PY="$SCRIPT_DIR/normalize-code-scanning.py"
[[ ! -f "$NORMALIZE_PY" ]] && NORMALIZE_PY="$SCRIPT_DIR/scripts/normalize-code-scanning.py"
if [[ -f "$NORMALIZE_PY" ]]; then
    python3 "$NORMALIZE_PY" "$ORG_LABEL" "$TARGET_DIR" "$RUN_ID" || echo "[!] Normalization failed (exit $?) — raw files still available"
fi

python3 "$SCRIPT_DIR/manifest.py" "$OUTDIR"

echo "[✓] Scan complete"
