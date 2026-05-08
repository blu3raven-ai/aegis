#!/bin/bash
set -euo pipefail

if [[ ! -x ./scripts/lifecycle-dependencies.sh ]]; then
  echo "[FAIL] lifecycle-dependencies.sh missing or not executable"
  exit 1
fi

bash -n ./scripts/lifecycle-dependencies.sh
echo "[PASS] lifecycle-dependencies.sh syntax OK"

grep -q "identityKey" ./scripts/lifecycle-dependencies.sh
echo "[PASS] lifecycle-dependencies.sh produces identityKey"

grep -q "stateCandidate" ./scripts/lifecycle-dependencies.sh
echo "[PASS] lifecycle-dependencies.sh produces stateCandidate"

grep -q "firstSeenCommit" ./scripts/lifecycle-dependencies.sh
echo "[PASS] lifecycle-dependencies.sh tracks firstSeenCommit"
