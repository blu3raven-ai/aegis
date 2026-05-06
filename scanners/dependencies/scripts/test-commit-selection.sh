#!/bin/bash
set -euo pipefail

grep -q "GIT_ASKPASS" ./run.sh
echo "[PASS] run.sh uses GIT_ASKPASS for secure cloning"

grep -q "git clone --depth 1" ./run.sh
echo "[PASS] run.sh uses shallow clone"

grep -q "git rev-parse HEAD" ./run.sh
echo "[PASS] run.sh captures HEAD SHA"
