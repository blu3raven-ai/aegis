#!/bin/bash
# extract-context.sh — extract code context (window, imports, file_class) per SAST finding
# Usage: extract-context.sh CLONE_DIR REPO_OUTPUT_DIR
# Output: REPO_OUTPUT_DIR/context.json
set -euo pipefail

CLONE_DIR="$1"
REPO_OUTPUT_DIR="$2"
SARIF_FILE="$REPO_OUTPUT_DIR/opengrep.json"
CONTEXT_FILE="$REPO_OUTPUT_DIR/context.json"

if [[ ! -f "$SARIF_FILE" ]]; then
    echo '{}' > "$CONTEXT_FILE"
    exit 0
fi

classify_file() {
    local path="$1"
    if echo "$path" | grep -qiE '(test|spec|mock|__tests__|fixtures|testdata|_test\.go|\.test\.)'; then
        echo "test"
    elif echo "$path" | grep -qE '(\.pb\.go$|\.generated\.|/dist/|/build/|\.min\.js$)'; then
        echo "generated"
    elif echo "$path" | grep -qE '(^|/)vendor/|(^|/)node_modules/|(^|/)third_party/'; then
        echo "vendor"
    else
        echo "source"
    fi
}

extract_imports() {
    local file="$1"
    [[ ! -f "$file" ]] && return
    awk '
        /^[[:space:]]*(import |from [a-zA-Z_]|require[( ]|#include |use [a-zA-Z\\]|package [a-zA-Z])/ {
            print; found=1; next
        }
        found && /^[[:space:]]*$/ { next }
        found { exit }
    ' "$file" 2>/dev/null | head -50
}

extract_window() {
    local file="$1"
    local line="$2"
    [[ ! -f "$file" ]] && return
    local start=$(( line > 40 ? line - 40 : 1 ))
    sed -n "${start},$((line + 40))p" "$file" 2>/dev/null | head -c 8192
}

# Extract unique (file, line) pairs from SARIF
echo '{}' > "$CONTEXT_FILE"

while IFS=$'\t' read -r rel_path line; do
    [[ -z "$rel_path" || "$line" == "0" ]] && continue

    # Reject paths that could escape the clone directory
    if [[ "$rel_path" == /* ]] || [[ "$rel_path" == *..* ]]; then
        continue
    fi
    abs_path=$(realpath -m "$CLONE_DIR/$rel_path" 2>/dev/null || echo "")
    if [[ -z "$abs_path" ]] || [[ "$abs_path" != "$CLONE_DIR"/* ]]; then
        continue
    fi
    file_class=$(classify_file "$rel_path")
    imports=$(extract_imports "$abs_path" || true)
    window=$(extract_window "$abs_path" "$line" || true)
    key="${rel_path}:${line}"

    jq --arg key "$key" \
       --arg fc "$file_class" \
       --arg imp "$imports" \
       --arg win "$window" \
       '. + {($key): {file_class: $fc, imports: $imp, code_window: $win}}' \
       "$CONTEXT_FILE" > "${CONTEXT_FILE}.tmp" && mv "${CONTEXT_FILE}.tmp" "$CONTEXT_FILE"

done < <(
    jq -r '
        .runs[]?.results[]? |
        ((.locations[0]?.physicalLocation.artifactLocation.uri) // "") + "\t" +
        ((.locations[0]?.physicalLocation.region.startLine // 0) | tostring)
    ' "$SARIF_FILE" 2>/dev/null | sort -u
)

echo "[✓] Context extracted for $(jq 'keys | length' "$CONTEXT_FILE") findings → $CONTEXT_FILE"
