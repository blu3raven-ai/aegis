#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source /scanner/shared/lib.sh
setup_output_dir

ORG_LABEL="${ORG_LABEL:-default}"
SCAN_DEPTH="${SCAN_DEPTH:-light}"
GIT_REPOS="${GIT_REPOS:-}"
GIT_TOKEN="${GIT_TOKEN:-}"
START_DATE="${SCAN_START_DATE:-}"

check_dependencies trufflehog betterleaks jq

if [[ -z "$GIT_REPOS" ]]; then
    echo "[!] No GIT_REPOS specified — nothing to scan"
    exit 1
fi

if [[ "$SCAN_DEPTH" != "deep" && "$SCAN_DEPTH" != "light" && "$SCAN_DEPTH" != "ai_enhanced" ]]; then
    echo "[!] Invalid SCAN_DEPTH: $SCAN_DEPTH"
    exit 1
fi

scan_repository() {
    local repo_url="$1"
    local target_dir="$2"
    local start_date="${3:-}"

    local repo_name
    repo_name=$(repo_name_from_url "$repo_url")

    log_scanning "$repo_name"

    local repo_output_dir="$target_dir/$repo_name"
    mkdir -p "$repo_output_dir"
    local temp_dir
    temp_dir=$(mktemp -d)
    local original_dir
    original_dir=$(pwd)

    # GIT_ASKPASS keeps the token off the process list and .git/config
    local askpass=""
    if [[ -n "$GIT_TOKEN" ]]; then
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

    if [[ "$SCAN_DEPTH" == "light" ]]; then
        if ! "${clone_env[@]}" git clone --depth 1 "$repo_url" "$temp_dir" >/dev/null 2>&1; then
            echo "[!] Failed to clone $repo_name"
            rm -rf "$temp_dir" "$repo_output_dir"
            return 0
        fi
    else
        if ! "${clone_env[@]}" git clone "$repo_url" "$temp_dir" >/dev/null 2>&1; then
            echo "[!] Failed to clone $repo_name"
            rm -rf "$temp_dir" "$repo_output_dir"
            return 0
        fi
    fi

    cd "$temp_dir"
    mkdir -p "$repo_output_dir"

    # HEAD SHA enriches light-scan results (trufflehog filesystem mode omits git metadata)
    local head_sha=""
    if [[ -d "$temp_dir/.git" ]]; then
        head_sha=$(git -C "$temp_dir" rev-parse HEAD 2>/dev/null || echo "")
    fi

    if [[ "$SCAN_DEPTH" == "light" ]]; then
        trufflehog filesystem "$temp_dir" \
            --no-update \
            --results=verified,unverified,unknown \
            --json \
            > "$repo_output_dir/trufflehog_raw.json" \
            2>/dev/null || true

        if [[ -n "$head_sha" && -s "$repo_output_dir/trufflehog_raw.json" ]]; then
            jq -c '. + {"Commit": "'"$head_sha"'"}' "$repo_output_dir/trufflehog_raw.json" \
                > "$repo_output_dir/trufflehog.json" 2>/dev/null || \
                mv "$repo_output_dir/trufflehog_raw.json" "$repo_output_dir/trufflehog.json"
            rm -f "$repo_output_dir/trufflehog_raw.json"
        else
            [[ -f "$repo_output_dir/trufflehog_raw.json" ]] && \
                mv "$repo_output_dir/trufflehog_raw.json" "$repo_output_dir/trufflehog.json"
        fi

    elif [[ "$SCAN_DEPTH" == "deep" ]]; then
        if [[ -n "$start_date" ]]; then
            local has_commits
            has_commits=$(git rev-list --after="$start_date" HEAD 2>/dev/null | head -1 || echo "")

            if [[ -n "$has_commits" ]]; then
                local anchor_commit
                anchor_commit=$(git rev-list --until="$start_date" HEAD 2>/dev/null | head -1 || echo "")

                if [[ -n "$anchor_commit" ]]; then
                    trufflehog git "file://$temp_dir" \
                        --no-update \
                        --results=verified,unverified,unknown \
                        --json \
                        --since-commit="$anchor_commit" \
                        > "$repo_output_dir/trufflehog.json" \
                        2>/dev/null || true
                else
                    trufflehog git "file://$temp_dir" \
                        --no-update \
                        --results=verified,unverified,unknown \
                        --json \
                        > "$repo_output_dir/trufflehog.json" \
                        2>/dev/null || true
                fi
            else
                echo "[]" > "$repo_output_dir/trufflehog.json"
            fi
        else
            trufflehog git "file://$temp_dir" \
                --no-update \
                --results=verified,unverified,unknown \
                --json \
                > "$repo_output_dir/trufflehog.json" \
                2>/dev/null || true
        fi

    elif [[ "$SCAN_DEPTH" == "ai_enhanced" ]]; then
        local bl_raw="$repo_output_dir/betterleaks_raw.json"

        if [[ -n "$start_date" ]]; then
            betterleaks git "$temp_dir" \
                --report-format json \
                --report-path "$bl_raw" \
                --log-opts "--after=$start_date" \
                >/dev/null 2>&1 || true
        else
            betterleaks git "$temp_dir" \
                --report-format json \
                --report-path "$bl_raw" \
                >/dev/null 2>&1 || true
        fi

        # Enrich with source context while clone is still on disk
        if [[ -f "$bl_raw" ]] && [[ -s "$bl_raw" ]]; then
            python3 /scanner/enrich_context.py "$bl_raw" "$temp_dir" 3 >/dev/null 2>&1 || true
        fi

        # Classification runs in batch after all repos finish
    fi

    cd "$original_dir"

    cleanup_empty_results "$repo_output_dir"

    for f in "$repo_output_dir"/*.json; do
        [ -f "$f" ] && register_output "$f" "$repo_name"
    done

    log_finished "$repo_name"
}

cleanup_empty_results() {
    local dir="$1"
    shopt -s nullglob
    for json_file in "$dir"/*.json; do
        if [[ -f "$json_file" ]] && ([[ ! -s "$json_file" ]] || [[ "$(cat "$json_file" 2>/dev/null)" == "[]" ]]); then
            rm -f "$json_file"
        fi
    done
    shopt -u nullglob

    if [[ -d "$dir" ]] && [[ ! "$(ls -A "$dir" 2>/dev/null)" ]]; then
        rmdir "$dir" 2>/dev/null || true
    fi
}


# Exports for parallel execution
export -f scan_repository cleanup_empty_results repo_name_from_url log_scanning log_finished register_output
export SCAN_DEPTH RUN_ID
[[ -n "${GIT_TOKEN:-}" ]] && export GIT_TOKEN

# Main execution

# Only use start date for deep scans
if [[ ("$SCAN_DEPTH" == "deep" || "$SCAN_DEPTH" == "ai_enhanced") && -n "$START_DATE" ]]; then
    if ! [[ "$START_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        echo "[!] SCAN_START_DATE must be in YYYY-MM-DD format"
        exit 1
    fi
fi

export START_DATE

# Pre-warm ONNX model in background so it's ready after scanning
if [[ "$SCAN_DEPTH" == "ai_enhanced" ]]; then
    rm -f /tmp/.model_warmed
    python3 - <<'PYWARMUP' >/dev/null 2>&1 &
import onnxruntime as ort
import numpy as np
from transformers import AutoTokenizer
tokenizer = AutoTokenizer.from_pretrained("/scanner/model")
session = ort.InferenceSession("/scanner/model/model.onnx", providers=["CPUExecutionProvider"])
inputs = tokenizer(["warmup"], padding=True, truncation=True, max_length=16, return_tensors="np")
ort_names = {inp.name for inp in session.get_inputs()}
filtered = {k: v for k, v in dict(inputs).items() if k in ort_names}
session.run(["logits"], filtered)
open("/tmp/.model_warmed", "w").close()
PYWARMUP
    MODEL_WARMUP_PID=$!
fi

TARGET_DIR="$OUTDIR"
mkdir -p "$TARGET_DIR"

REPO_LIST=$(parse_repos "$GIT_REPOS")
REPO_COUNT=$(echo "$REPO_LIST" | wc -l)
echo "[+] $REPO_COUNT repositories to scan"

PARALLEL_SCRIPT=$(mktemp /tmp/parallel_scan.XXXXXX.sh)
cat > "$PARALLEL_SCRIPT" << 'EOF'
#!/bin/bash
repo_url="$1"
target_dir="$2"
start_date="$3"
scan_repository "$repo_url" "$target_dir" "$start_date"
exit 0
EOF
chmod 700 "$PARALLEL_SCRIPT"

if command -v parallel >/dev/null 2>&1; then
    echo "$REPO_LIST" | parallel --line-buffer -j "$CONCURRENCY" "$PARALLEL_SCRIPT" "{}" "$TARGET_DIR" "$START_DATE" || true
else
    echo "$REPO_LIST" | xargs -I {} -P "$CONCURRENCY" "$PARALLEL_SCRIPT" "{}" "$TARGET_DIR" "$START_DATE" || true
fi

rm -f "$PARALLEL_SCRIPT"

# Batch AI classification (ai_enhanced only)
if [[ "$SCAN_DEPTH" == "ai_enhanced" ]]; then
    if [[ -n "${MODEL_WARMUP_PID:-}" ]]; then
        wait "$MODEL_WARMUP_PID" 2>/dev/null || true
    fi
    echo "[+] Running AI classification on $(find "$TARGET_DIR" -name 'betterleaks_raw.json' | wc -l) files"
    python3 /scanner/classify.py --batch "$TARGET_DIR"
    echo "[✓] Classification complete — $(find "$TARGET_DIR" -name 'betterleaks.json' | wc -l) classified files produced"
fi

# Normalization
NORMALIZE_PY="$SCRIPT_DIR/scripts/normalize-secrets.py"
[[ ! -f "$NORMALIZE_PY" ]] && NORMALIZE_PY="$SCRIPT_DIR/normalize-secrets.py"
if [[ -f "$NORMALIZE_PY" ]]; then
    echo "[+] Normalizing findings from $TARGET_DIR"
    python3 "$NORMALIZE_PY" "$ORG_LABEL" "$TARGET_DIR" "$RUN_ID" || echo "[!] Normalization failed (exit $?) — raw files still available"
    FINDINGS_SIZE=$(wc -l < "$TARGET_DIR/findings.jsonl" 2>/dev/null || echo 0)
    echo "[✓] Normalized $FINDINGS_SIZE findings → $TARGET_DIR/findings.jsonl"
fi

python3 "$SCRIPT_DIR/manifest.py" "$OUTDIR"

echo "[✓] Scan complete"
