#!/bin/bash
set -euo pipefail

grep -q "syft" ./run.sh
echo "[PASS] run.sh uses syft"

grep -q "grype" ./run.sh
echo "[PASS] run.sh uses grype"

grep -q "head-sha.txt" ./run.sh
echo "[PASS] run.sh writes head-sha.txt"
