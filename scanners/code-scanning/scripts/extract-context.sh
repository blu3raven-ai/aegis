#!/bin/bash
# extract-context.sh — extract code context (window, imports, file_class) per SAST finding
# Usage: extract-context.sh CLONE_DIR REPO_OUTPUT_DIR
# Output: REPO_OUTPUT_DIR/context.json
#
# Delegates to extract-context.py for a single-pass O(n) implementation.
# The old bash/jq loop ran jq once per finding (O(n²) reads/writes on
# context.json), which took several minutes on repos with 2000+ findings.
set -euo pipefail

CLONE_DIR="$1"
REPO_OUTPUT_DIR="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python3 "$SCRIPT_DIR/extract-context.py" "$CLONE_DIR" "$REPO_OUTPUT_DIR"
