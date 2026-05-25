#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source /scanner/shared/lib.sh
setup_output_dir

SCAN_MODE="${SCAN_MODE:-full}"
GIT_REPOS="${GIT_REPOS:-}"
GIT_TOKEN="${GIT_TOKEN:-}"
NVD_API_KEY="${NVD_API_KEY:-}"
GHSA_API_KEY="${GHSA_API_KEY:-}"
ADVISORY_PROVIDERS="${ADVISORY_PROVIDERS:-}"
CUSTOM_DB_PATH="${CUSTOM_DB_PATH:-}"
ARGUS_API_KEY="${ARGUS_API_KEY:-}"
ARGUS_ENDPOINT="${ARGUS_ENDPOINT:-}"

check_dependencies git syft grype jq

echo "[+] Checking Grype vulnerability database..."
if ! grype db check >/dev/null 2>&1; then
    echo "[+] Updating Grype vulnerability database..."
    if grype db update 2>&1; then
        echo "[✓] Grype DB updated successfully"
    else
        echo "[!] Grype DB update failed — scanning may produce incomplete results"
    fi
else
    echo "[✓] Grype DB is current"
fi

# Build custom advisory DB from configured sources
build_custom_advisory_db() {
    if [[ -z "$ADVISORY_PROVIDERS" ]]; then
        return 0
    fi

    if ! command -v vunnel &>/dev/null || ! command -v grype-db &>/dev/null; then
        echo "[!] vunnel or grype-db not available — skipping custom advisory DB"
        return 0
    fi

    local work_dir
    work_dir=$(mktemp -d /tmp/vunnel-work.XXXXXX)

    local vunnel_config="$work_dir/vunnel.yaml"
    cat > "$vunnel_config" << YAML
root: ${work_dir}/data
providers:
  nvd:
    api_key: "${NVD_API_KEY}"
  github:
    token: "${GHSA_API_KEY}"
YAML

    echo "[+] Building custom advisory DB: providers=$ADVISORY_PROVIDERS"

    IFS=',' read -ra PROVIDERS <<< "$ADVISORY_PROVIDERS"
    for provider in "${PROVIDERS[@]}"; do
        provider=$(echo "$provider" | xargs)  # trim whitespace
        [[ -z "$provider" ]] && continue

        echo "[+] Fetching advisories from $provider..."
        if vunnel -c "$vunnel_config" run "$provider" 2>&1; then
            echo "[+] Fetched: $provider"
        else
            echo "[!] vunnel failed for $provider (continuing)"
        fi
    done

    echo "[+] Compiling custom Grype DB..."
    local build_dir="$work_dir/build"
    mkdir -p "$build_dir"

    if (cd "$work_dir/data" && grype-db build -d "$build_dir" 2>&1); then
        local db_file
        db_file=$(find "$build_dir" -name "*.db" -type f | head -1)
        if [[ -n "$db_file" ]]; then
            CUSTOM_DB_PATH="$db_file"
            export CUSTOM_DB_PATH
            echo "[✓] Custom advisory DB ready: $db_file"
        else
            echo "[!] grype-db produced no DB file — continuing with built-in DB"
        fi
    else
        echo "[!] grype-db build failed — continuing with built-in DB"
    fi
}

download_argus_db() {
    if [ -z "$ARGUS_API_KEY" ] || [ -z "$ARGUS_ENDPOINT" ]; then
        return
    fi

    echo "[+] Downloading Argus threat intelligence DB..."
    local status
    status=$(curl -fsSL -w "%{http_code}" \
        -H "Authorization: Bearer $ARGUS_API_KEY" \
        "$ARGUS_ENDPOINT/api/db/latest" \
        -o /tmp/argus.db 2>/dev/null)

    if [ "$status" = "200" ] && [ -s /tmp/argus.db ]; then
        export CUSTOM_DB_PATH="/tmp/argus.db"
        echo "[✓] Argus DB downloaded"
    else
        echo "[!] Argus DB download failed (HTTP $status) — using built-in DB only"
    fi
}

run_grype_match() {
    local sbom_path="$1"
    local output_path="$2"

    local grype_args=("sbom:${sbom_path}" "-o" "json" "--quiet")
    if [[ -n "$CUSTOM_DB_PATH" && -f "$CUSTOM_DB_PATH" ]]; then
        grype_args+=("--db" "$CUSTOM_DB_PATH")
    fi

    local grype_stderr
    grype_stderr=$(mktemp)
    if grype "${grype_args[@]}" > "$output_path" 2>"$grype_stderr"; then
        rm -f "$grype_stderr"
        return 0
    else
        local exit_code=$?
        # Exit 1 = vulnerabilities found (not an error)
        if [[ $exit_code -eq 1 ]]; then
            rm -f "$grype_stderr"
            return 0
        fi
        echo "[!] Grype failed (exit $exit_code) for $(basename "$sbom_path"): $(cat "$grype_stderr" 2>/dev/null | tail -3)" >&2
        rm -f "$output_path" "$grype_stderr"
        return $exit_code
    fi
}

tag_sbom_source() {
    local sbom_file="$1"
    local tool_name="$2"
    if [ -s "$sbom_file" ]; then
        jq --arg tool "$tool_name" \
            '(.components // [])[] |= (.properties = ((.properties // []) + [{"name": "scanner:source", "value": $tool}]))' \
            "$sbom_file" > "${sbom_file}.tagged" 2>/dev/null && \
            mv "${sbom_file}.tagged" "$sbom_file"
    fi
}

scan_repository() {
    local repo_url="$1"
    local target_dir="$2"
    local repo_name
    repo_name=$(repo_name_from_url "$repo_url")
    local repo_output_dir="$target_dir/$repo_name"
    mkdir -p "$repo_output_dir"

    log_scanning "$repo_name"

    local temp_dir
    temp_dir=$(mktemp -d)
    if ! clone_repo "$repo_url" "$temp_dir"; then
        echo "[!] Failed to clone $repo_name"
        log_finished "$repo_name"
        rm -rf "$temp_dir"
        return 1
    fi

    local head_sha
    head_sha=$(git -C "$temp_dir" rev-parse HEAD 2>/dev/null || echo "unknown")
    echo "$head_sha" > "$repo_output_dir/head-sha.txt"

    # Unset credentials — SBOM tools may invoke install scripts that inherit env
    unset GIT_TOKEN

    # Syft: lock files + binary analysis
    local syft_ok=false
    if syft "$temp_dir" -o cyclonedx-json --parallelism 2 > "$repo_output_dir/syft-sbom.cdx.json" 2>/dev/null; then
        tag_sbom_source "$repo_output_dir/syft-sbom.cdx.json" "syft"
        syft_ok=true
    else
        echo "[!] Syft failed for $repo_name"
    fi

    # cdxgen: resolves transitive dependency tree
    local cdxgen_ok=false
    if cdxgen -o "$repo_output_dir/cdxgen-sbom.cdx.json" "$temp_dir" --no-recurse >/dev/null 2>&1; then
        if [ -s "$repo_output_dir/cdxgen-sbom.cdx.json" ]; then
            tag_sbom_source "$repo_output_dir/cdxgen-sbom.cdx.json" "cdxgen"
            cdxgen_ok=true
        fi
    else
        echo "[!] cdxgen failed for $repo_name — Syft SBOM only"
    fi

    # Merge SBOMs (cyclonedx-cli deduplicates by PURL)
    if $syft_ok && $cdxgen_ok; then
        # Subshell suppresses "Aborted" signal message from reaching log
        if ! (DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=true cyclonedx merge \
            --input-files "$repo_output_dir/syft-sbom.cdx.json" "$repo_output_dir/cdxgen-sbom.cdx.json" \
            --output-file "$repo_output_dir/sbom.cdx.json" \
            --output-format json >/dev/null 2>&1); then
            cp "$repo_output_dir/syft-sbom.cdx.json" "$repo_output_dir/sbom.cdx.json"
        fi
    elif $syft_ok; then
        cp "$repo_output_dir/syft-sbom.cdx.json" "$repo_output_dir/sbom.cdx.json"
    elif $cdxgen_ok; then
        cp "$repo_output_dir/cdxgen-sbom.cdx.json" "$repo_output_dir/sbom.cdx.json"
    else
        echo "[!] Both SBOM generators failed for $repo_name — skipping"
        log_finished "$repo_name"
        rm -rf "$temp_dir"
        return 1
    fi

    # Extract manifests for snippet enrichment
    if [ -s "$repo_output_dir/sbom.cdx.json" ]; then
        local manifests_dir="$repo_output_dir/manifests"
        mkdir -p "$manifests_dir"
        local manifest_paths
        manifest_paths=$(jq -r '.components[]? | (.properties // [])[] | select(.name == "cdx:npm:package:path" or .name == "syft:location:0:path") | .value // empty' "$repo_output_dir/sbom.cdx.json" 2>/dev/null | sort -u)

        # Fallback: Syft SBOM has location data
        if [ -z "$manifest_paths" ] && [ -s "$repo_output_dir/syft-sbom.cdx.json" ]; then
            manifest_paths=$(jq -r '.components[]? | (.properties // [])[] | select(.name | startswith("syft:location")) | .value // empty' "$repo_output_dir/syft-sbom.cdx.json" 2>/dev/null | sort -u)
        fi

        if [ -n "$manifest_paths" ]; then
            while IFS= read -r mpath; do
                # Syft paths are root-relative — strip leading slash before security check
                local clean_mpath="${mpath#/}"
                # Reject paths that could escape the clone directory
                if [[ "$clean_mpath" == *..* ]]; then
                    continue
                fi
                local resolved
                resolved=$(realpath -m "$temp_dir/$clean_mpath" 2>/dev/null || echo "")
                if [[ -z "$resolved" ]] || [[ "$resolved" != "$temp_dir"/* ]]; then
                    continue
                fi
                if [ -f "$resolved" ]; then
                    local safe_name
                    safe_name=$(echo "$clean_mpath" | sed 's|/|__|g')
                    cp "$resolved" "$manifests_dir/$safe_name" 2>/dev/null
                fi
            done <<< "$manifest_paths"
        fi
    fi

    if [ -s "$repo_output_dir/sbom.cdx.json" ]; then
        run_grype_match "$repo_output_dir/sbom.cdx.json" "$repo_output_dir/findings.json"
        register_output "$repo_output_dir/sbom.cdx.json" "$repo_name"
    fi

    log_finished "$repo_name"
    rm -rf "$temp_dir"
}

export -f scan_repository repo_name_from_url run_grype_match download_argus_db tag_sbom_source \
    clone_repo log_scanning log_finished register_output
[[ -n "${GIT_TOKEN:-}" ]] && export GIT_TOKEN
export RUN_ID SCAN_MODE CUSTOM_DB_PATH OUTDIR

if [[ "$SCAN_MODE" == "full" || "$SCAN_MODE" == "advisories_only" ]]; then
    build_custom_advisory_db
fi

download_argus_db

# Advisories-only mode
if [[ "$SCAN_MODE" == "advisories_only" ]]; then
    SBOM_INPUT_DIR="/scanner/input/sboms"

    # Download SBOMs from object storage if not mounted locally
    if [[ ! -d "$SBOM_INPUT_DIR" || -z "$(ls -A "$SBOM_INPUT_DIR" 2>/dev/null)" ]]; then
        if [[ -n "${S3_ENDPOINT:-}" && -n "${S3_ACCESS_KEY:-}" ]]; then
            python3 "$SCRIPT_DIR/scripts/download-sboms.py" "$SBOM_INPUT_DIR" || {
                echo "[!] Failed to download SBOMs"
                exit 0
            }
        else
            echo "[!] No SBOMs available — nothing to match"
            exit 0
        fi
    fi

    SBOM_COUNT=$(find "$SBOM_INPUT_DIR" -name "*.json" | wc -l | tr -d ' ')
    echo "[+] advisories_only mode: matching $SBOM_COUNT SBOMs"

    ORG_LABEL="${ORG_LABEL:-default}"
    TARGET_DIR="$OUTDIR"

    for sbom_file in "$SBOM_INPUT_DIR"/*.json; do
        [[ ! -f "$sbom_file" ]] && continue
        repo_key=$(basename "$sbom_file" .json)

        repo_name=$(echo "$repo_key" | sed 's|__|/|g')
        repo_output_dir="$TARGET_DIR/$repo_name"
        mkdir -p "$repo_output_dir"

        cp "$sbom_file" "$repo_output_dir/sbom.cdx.json"

        if run_grype_match "$sbom_file" "$repo_output_dir/findings.json"; then
            echo "[+] Matched: $repo_name"
        else
            echo "[!] Grype failed for $repo_name"
        fi
    done

    echo "[✓] Scan complete"

    if [[ -f "$SCRIPT_DIR/scripts/normalize-dependencies.py" ]]; then
        python3 "$SCRIPT_DIR/scripts/normalize-dependencies.py" "$ORG_LABEL" "$TARGET_DIR" "$RUN_ID" || echo "[!] Normalization failed (exit $?) — raw files still available"
    fi
    python3 "$SCRIPT_DIR/manifest.py" "$OUTDIR"
    exit 0
fi

# Main execution (full / sbom_only)
ORG_LABEL="${ORG_LABEL:-default}"
TARGET_DIR="$OUTDIR"
mkdir -p "$TARGET_DIR"

if [[ -z "$GIT_REPOS" ]]; then
    echo "[!] No GIT_REPOS specified — nothing to scan"
    exit 0
fi

REPO_LIST=$(parse_repos "$GIT_REPOS")
REPO_COUNT=$(echo "$REPO_LIST" | wc -l | tr -d ' ')
echo "[+] $REPO_COUNT repositories to scan (mode: $SCAN_MODE)"

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
NORMALIZE_PY="$SCRIPT_DIR/scripts/normalize-dependencies.py"
[[ ! -f "$NORMALIZE_PY" ]] && NORMALIZE_PY="$SCRIPT_DIR/normalize-dependencies.py"
if [[ -f "$NORMALIZE_PY" ]]; then
    python3 "$NORMALIZE_PY" "$ORG_LABEL" "$TARGET_DIR" "$RUN_ID" || echo "[!] Normalization failed (exit $?) — raw files still available"
fi

python3 "$SCRIPT_DIR/manifest.py" "$OUTDIR"

echo "[✓] Scan complete"
