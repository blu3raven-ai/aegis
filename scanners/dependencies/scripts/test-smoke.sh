#!/bin/bash
# Run from scanner root: bash scripts/test-smoke.sh
set -euo pipefail

if [[ ! -x ./run.sh ]]; then
  echo "[FAIL] run.sh missing or not executable"
  exit 1
fi

bash -n ./run.sh
echo "[PASS] run.sh syntax OK"

if [[ ! -x ./scripts/normalize-dependencies.sh ]]; then
  echo "[FAIL] scripts/normalize-dependencies.sh missing or not executable"
  exit 1
fi

bash -n ./scripts/normalize-dependencies.sh
echo "[PASS] normalize-dependencies.sh syntax OK"
