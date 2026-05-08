#!/bin/bash
# Run from scanner root: bash scripts/test-normalize.sh
set -euo pipefail

NORMALIZE=./scripts/normalize-dependencies.sh

if [[ ! -x "$NORMALIZE" ]]; then
  echo "[FAIL] $NORMALIZE missing or not executable"
  exit 1
fi

grep -q "findings.jsonl" "$NORMALIZE"
echo "[PASS] normalize-dependencies.sh writes findings.jsonl"

grep -q "summary.json" "$NORMALIZE"
echo "[PASS] normalize-dependencies.sh writes summary.json"

grep -q "findings-lifecycle.jsonl" "$NORMALIZE"
echo "[PASS] normalize-dependencies.sh produces lifecycle output"

grep -q "grype.json" "$NORMALIZE"
echo "[PASS] normalize-dependencies.sh reads grype output"
