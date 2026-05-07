#!/bin/bash
# run-reachability.sh — call graph reachability wrapper
# Usage: run-reachability.sh <clone_dir> <repo_output_dir>
set -euo pipefail

CLONE_DIR="$1"
REPO_OUTPUT_DIR="$2"
SARIF_FILE="$REPO_OUTPUT_DIR/opengrep.json"
OUTPUT_FILE="$REPO_OUTPUT_DIR/reachability.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$SARIF_FILE" ]]; then
    echo '{}' > "$OUTPUT_FILE"
    exit 0
fi

if ! command -v python3 &>/dev/null; then
    echo '{}' > "$OUTPUT_FILE"
    exit 0
fi

python3 "$SCRIPT_DIR/reachability.py" "$CLONE_DIR" "$SARIF_FILE" "$OUTPUT_FILE" 2>&1 || {
    echo "[!] reachability.py failed for $REPO_OUTPUT_DIR — writing empty output"
    echo '{}' > "$OUTPUT_FILE"
}
