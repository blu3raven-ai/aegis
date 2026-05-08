#!/bin/bash
# Common functions for all scanner entrypoints.
set -euo pipefail

setup_output_dir() {
    OUTDIR="/scanner/output/${JOB_ID:-unknown}"
    CONCURRENCY="${CONCURRENCY:-4}"
    RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
    mkdir -p "$OUTDIR"
    export OUTDIR CONCURRENCY RUN_ID

    # Docker volumes may be initialized with root ownership
    for cache_dir in /home/scanner/.cache/grype /home/scanner/.cache/trivy; do
        if [ -d "$cache_dir" ] && [ ! -w "$cache_dir" ]; then
            echo "[!] Cache directory $cache_dir not writable — this may cause scan failures"
        fi
    done
}

check_dependencies() {
    local missing_deps=()
    for cmd in "$@"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    if ! command -v parallel &>/dev/null && ! command -v xargs &>/dev/null; then
        missing_deps+=("parallel or xargs")
    fi
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo "ERROR: Missing required dependencies: ${missing_deps[*]}"
        exit 1
    fi
}

repo_name_from_url() {
    local url="$1"
    local path
    path="${url%.git}"
    path="${path%/}"
    basename "$path"
}

clone_repo() {
    local url="$1"
    local dest="$2"
    local token="${GIT_TOKEN:-}"

    # SECURITY: Only allow HTTPS URLs to prevent SSH/file/git protocol abuse
    if [[ "$url" != https://* ]]; then
        echo "[!] Rejected non-HTTPS git URL: $url" >&2
        return 1
    fi

    local auth_url="$url"
    if [[ -n "$token" ]]; then
        auth_url="${url/https:\/\//https:\/\/x-access-token:${token}@}"
    fi

    git clone --depth 1 --single-branch "$auth_url" "$dest" 2>/dev/null
}

run_parallel() {
    local jobs="$1"
    shift
    if command -v parallel &>/dev/null; then
        parallel -j "$jobs" "$@"
    else
        xargs -P "$jobs" -I {} "$@" {}
    fi
}

# Progress markers (runner parses these for progress reporting)
log_scanning() {
    local target="$1"
    echo "[+] Scanning repo: $target"
}

log_scanning_image() {
    local target="$1"
    echo "[+] Scanning image: $target"
}

log_finished() {
    local target="$1"
    echo "[✓] Finished: $target"
}

# Register output file with manifest for streaming upload
register_output() {
    local file_path="$1"
    local repo_name="$2"
    [ -s "$file_path" ] || return 0
    MANIFEST_OUTDIR="$OUTDIR" MANIFEST_FILE="$file_path" MANIFEST_REPO="$repo_name" \
        python3 -c "
import os; from manifest import record_output
record_output(os.environ['MANIFEST_OUTDIR'], os.environ['MANIFEST_FILE'], os.environ['MANIFEST_REPO'])
" 2>/dev/null || true
}

# Accepts comma-separated, newline-separated, or file path
parse_repos() {
    local input="$1"
    if [[ -f "$input" ]]; then
        cat "$input"
    else
        echo "$input" | tr ',' '\n' | sed '/^$/d'
    fi
}
