#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAIL=0

# ── Fixture: simple Python call chain ─────────────────────────────────
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/routes"
cat > "$TMPDIR/routes/upload.py" << 'PYEOF'
@app.post("/upload")
def handle_upload(request):
    process_file(request.data)

def process_file(data):
    write_temp(data)

def write_temp(data):
    open("/tmp/x", "w").write(data)
PYEOF

# SARIF with a finding in write_temp (line 8)
cat > "$TMPDIR/opengrep.json" << 'SARIF'
{
  "runs": [{
    "tool": {"driver": {"rules": [{"id": "test.path-traversal"}]}},
    "results": [{
      "ruleId": "test.path-traversal",
      "level": "warning",
      "message": {"text": "Path traversal"},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "routes/upload.py"},
          "region": {"startLine": 8, "endLine": 8, "snippet": {"text": "  open(\"/tmp/x\", \"w\").write(data)"}}
        }
      }]
    }]
  }]
}
SARIF

python3.12 "$SCRIPT_DIR/reachability.py" "$TMPDIR" "$TMPDIR/opengrep.json" "$TMPDIR/reachability.json"

verdict=$(jq -r '."routes/upload.py:8".verdict // "missing"' "$TMPDIR/reachability.json")
if [[ "$verdict" == "reachable" ]]; then
    echo "✓ write_temp is reachable from @app.post entry point"
else
    echo "✗ FAIL: expected reachable, got '$verdict'"
    FAIL=1
fi

# ── Fixture: absolute paths in SARIF URIs (Opengrep behaviour) ────────
TMPDIR3=$(mktemp -d)
trap 'rm -rf "$TMPDIR" "$TMPDIR2" "$TMPDIR3"' EXIT

mkdir -p "$TMPDIR3/routes"
cat > "$TMPDIR3/routes/upload.py" << 'PYEOF'
@app.post("/upload")
def handle_upload(request):
    process_file(request.data)

def process_file(data):
    write_temp(data)

def write_temp(data):
    open("/tmp/x", "w").write(data)
PYEOF

# SARIF URIs are absolute paths (as Opengrep writes them)
cat > "$TMPDIR3/opengrep.json" << SARIF
{
  "runs": [{
    "tool": {"driver": {"rules": [{"id": "test.path-traversal"}]}},
    "results": [{
      "ruleId": "test.path-traversal",
      "level": "warning",
      "message": {"text": "Path traversal"},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "$TMPDIR3/routes/upload.py"},
          "region": {"startLine": 8, "endLine": 8}
        }
      }]
    }]
  }]
}
SARIF

python3.12 "$SCRIPT_DIR/reachability.py" "$TMPDIR3" "$TMPDIR3/opengrep.json" "$TMPDIR3/reachability.json"

abs_key="$TMPDIR3/routes/upload.py:8"
verdict3=$(jq -r --arg k "$abs_key" '.[$k].verdict // "missing"' "$TMPDIR3/reachability.json")
if [[ "$verdict3" == "reachable" ]]; then
    echo "✓ absolute-path SARIF URI: write_temp is reachable"
else
    echo "✗ FAIL: absolute-path SARIF URI: expected reachable, got '$verdict3'"
    FAIL=1
fi

# ── Fixture: dead function ─────────────────────────────────────────────
TMPDIR2=$(mktemp -d)
trap 'rm -rf "$TMPDIR" "$TMPDIR2"' EXIT

mkdir -p "$TMPDIR2/utils"
cat > "$TMPDIR2/utils/dead.py" << 'PYEOF'
def dead_function():
    open("/etc/passwd")
PYEOF

mkdir -p "$TMPDIR2/routes"
cat > "$TMPDIR2/routes/app.py" << 'PYEOF'
@app.get("/")
def index():
    return "ok"
PYEOF

cat > "$TMPDIR2/opengrep.json" << 'SARIF'
{
  "runs": [{
    "tool": {"driver": {"rules": [{"id": "test.path"}]}},
    "results": [{
      "ruleId": "test.path",
      "level": "warning",
      "message": {"text": "path issue"},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "utils/dead.py"},
          "region": {"startLine": 2, "endLine": 2}
        }
      }]
    }]
  }]
}
SARIF

python3.12 "$SCRIPT_DIR/reachability.py" "$TMPDIR2" "$TMPDIR2/opengrep.json" "$TMPDIR2/reachability.json"

verdict2=$(jq -r '."utils/dead.py:2".verdict // "missing"' "$TMPDIR2/reachability.json")
if [[ "$verdict2" == "unreachable" ]]; then
    echo "✓ dead_function is unreachable"
else
    echo "✗ FAIL: expected unreachable, got '$verdict2'"
    FAIL=1
fi

# ── Fixture: module-level secret (not inside any function) → reachable ──
TMPDIR4=$(mktemp -d)
trap 'rm -rf "$TMPDIR" "$TMPDIR2" "$TMPDIR3" "$TMPDIR4"' EXIT

mkdir -p "$TMPDIR4/config"
cat > "$TMPDIR4/config/settings.py" << 'PYEOF'
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PYEOF

cat > "$TMPDIR4/opengrep.json" << 'SARIF'
{
  "runs": [{
    "tool": {"driver": {"rules": [{"id": "test.aws-key"}]}},
    "results": [{
      "ruleId": "test.aws-key",
      "level": "error",
      "message": {"text": "Hardcoded AWS key"},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "config/settings.py"},
          "region": {"startLine": 1, "endLine": 1}
        }
      }]
    }]
  }]
}
SARIF

python3.12 "$SCRIPT_DIR/reachability.py" "$TMPDIR4" "$TMPDIR4/opengrep.json" "$TMPDIR4/reachability.json"

verdict4=$(jq -r '."config/settings.py:1".verdict // "missing"' "$TMPDIR4/reachability.json")
if [[ "$verdict4" == "reachable" ]]; then
    echo "✓ module-level secret in config/ is reachable"
else
    echo "✗ FAIL: expected reachable for module-level secret, got '$verdict4'"
    FAIL=1
fi

# ── Fixture: module-level secret in archived/ → unreachable ─────────────
TMPDIR5=$(mktemp -d)
trap 'rm -rf "$TMPDIR" "$TMPDIR2" "$TMPDIR3" "$TMPDIR4" "$TMPDIR5"' EXIT

mkdir -p "$TMPDIR5/archived"
cat > "$TMPDIR5/archived/old_script.py" << 'PYEOF'
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
PYEOF

cat > "$TMPDIR5/opengrep.json" << 'SARIF'
{
  "runs": [{
    "tool": {"driver": {"rules": [{"id": "test.aws-key"}]}},
    "results": [{
      "ruleId": "test.aws-key",
      "level": "error",
      "message": {"text": "Hardcoded AWS key"},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "archived/old_script.py"},
          "region": {"startLine": 1, "endLine": 1}
        }
      }]
    }]
  }]
}
SARIF

python3.12 "$SCRIPT_DIR/reachability.py" "$TMPDIR5" "$TMPDIR5/opengrep.json" "$TMPDIR5/reachability.json"

verdict5=$(jq -r '."archived/old_script.py:1".verdict // "missing"' "$TMPDIR5/reachability.json")
if [[ "$verdict5" == "unreachable" ]]; then
    echo "✓ module-level secret in archived/ is unreachable"
else
    echo "✗ FAIL: expected unreachable for archived/ secret, got '$verdict5'"
    FAIL=1
fi

exit $FAIL
