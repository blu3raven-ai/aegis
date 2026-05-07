#!/bin/bash
# Run from scanner root: bash scripts/test-extract-context.sh
set -euo pipefail

SCRIPT="./scripts/extract-context.sh"
PASS=0; FAIL=0

check() {
    local desc="$1"; local result="$2"
    if [[ "$result" == "pass" ]]; then
        echo "[PASS] $desc"; PASS=$(( PASS + 1 ))
    else
        echo "[FAIL] $desc"; FAIL=$(( FAIL + 1 ))
    fi
}

# Setup temp dirs
TMP=$(mktemp -d)
CLONE="$TMP/clone"
OUTPUT="$TMP/output"
mkdir -p "$CLONE/src" "$OUTPUT"

# Create a sample Python file
cat > "$CLONE/src/app.py" << 'PYEOF'
import os
import flask
from flask import request

def get_user():
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + user_id
    return query
PYEOF

# Create a minimal SARIF pointing to line 6
cat > "$OUTPUT/opengrep.json" << 'SARIFEOF'
{
  "runs": [{
    "tool": {"driver": {"name": "opengrep", "rules": []}},
    "results": [{
      "ruleId": "python.lang.security.audit.sqli.sql-injection",
      "level": "error",
      "message": {"text": "SQL injection"},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "src/app.py"},
          "region": {"startLine": 6, "snippet": {"text": "query = ..."}}
        }
      }]
    }]
  }]
}
SARIFEOF

bash "$SCRIPT" "$CLONE" "$OUTPUT"

# Assertions
[[ -f "$OUTPUT/context.json" ]] && check "context.json created" "pass" || check "context.json created" "fail"

key_count=$(jq 'keys | length' "$OUTPUT/context.json")
[[ "$key_count" -ge 1 ]] && check "at least one context entry" "pass" || check "at least one context entry" "fail"

file_class=$(jq -r '.["src/app.py:6"].file_class' "$OUTPUT/context.json")
[[ "$file_class" == "source" ]] && check "file_class=source for src/app.py" "pass" || check "file_class=source for src/app.py: got $file_class" "fail"

imports=$(jq -r '.["src/app.py:6"].imports' "$OUTPUT/context.json")
echo "$imports" | grep -q "import os" && check "imports extracted" "pass" || check "imports extracted: got '$imports'" "fail"

code_window=$(jq -r '.["src/app.py:6"].code_window' "$OUTPUT/context.json")
echo "$code_window" | grep -q "get_user" && check "code_window contains function" "pass" || check "code_window contains function" "fail"

# Test: vendor classification
mkdir -p "$CLONE/node_modules/lib"
cat > "$CLONE/node_modules/lib/util.js" << 'JSEOF'
const x = eval(input)
JSEOF
cat > "$OUTPUT/opengrep.json" << 'SARIFEOF2'
{
  "runs": [{
    "tool": {"driver": {"name": "opengrep", "rules": []}},
    "results": [{
      "ruleId": "js.eval",
      "level": "warning",
      "message": {"text": "eval"},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "node_modules/lib/util.js"},
          "region": {"startLine": 1}
        }
      }]
    }]
  }]
}
SARIFEOF2

bash "$SCRIPT" "$CLONE" "$OUTPUT"
vendor_class=$(jq -r '.["node_modules/lib/util.js:1"].file_class' "$OUTPUT/context.json")
[[ "$vendor_class" == "vendor" ]] && check "node_modules classified as vendor" "pass" || check "node_modules classified as vendor: got $vendor_class" "fail"

# Test: no SARIF → empty context
rm -f "$OUTPUT/opengrep.json"
bash "$SCRIPT" "$CLONE" "$OUTPUT"
empty=$(jq 'keys | length' "$OUTPUT/context.json")
[[ "$empty" == "0" ]] && check "empty context when no SARIF" "pass" || check "empty context when no SARIF" "fail"

rm -rf "$TMP"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
