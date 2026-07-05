#!/usr/bin/env bash
set -euo pipefail

# Required pipe variables (declared in pipe.yml):
#   AEGIS_URL, AEGIS_API_KEY, SOURCE_ID
#   WAIT, FAIL_ON, POLL_TIMEOUT_SECONDS
# Bitbucket runtime vars:
#   BITBUCKET_COMMIT, BITBUCKET_BRANCH, BITBUCKET_PR_ID, BITBUCKET_BUILD_NUMBER

AEGIS_URL="${AEGIS_URL%/}"
WAIT="${WAIT:-true}"
FAIL_ON="${FAIL_ON:-none}"
POLL_TIMEOUT="${POLL_TIMEOUT_SECONDS:-1800}"

if [[ -z "${AEGIS_URL:-}" || -z "${AEGIS_API_KEY:-}" || -z "${SOURCE_ID:-}" ]]; then
  echo "ERROR: AEGIS_URL, AEGIS_API_KEY, and SOURCE_ID are required" >&2
  exit 1
fi
if [[ -z "${BITBUCKET_COMMIT:-}" ]]; then
  echo "ERROR: BITBUCKET_COMMIT not set; this pipe must run inside a Bitbucket Pipelines step" >&2
  exit 1
fi

pr_arg="null"
if [[ -n "${BITBUCKET_PR_ID:-}" ]]; then
  pr_arg="${BITBUCKET_PR_ID}"
fi

trigger_body=$(jq -n \
  --arg commit_sha "$BITBUCKET_COMMIT" \
  --arg branch "${BITBUCKET_BRANCH:-}" \
  --arg run_id "${BITBUCKET_BUILD_NUMBER:-}" \
  --argjson pr_number "$pr_arg" \
  '{commit_sha: $commit_sha,
    branch: ($branch | select(. != "")),
    pr_number: $pr_number,
    trigger_metadata: {ci_provider: "bitbucket", run_id: $run_id}}')

trigger_url="$AEGIS_URL/api/v1/sources/$SOURCE_ID/scans/trigger"

attempt=0
max_attempts=4
backoff=(5 15 45)
trigger_response=""
trigger_status=0

while (( attempt < max_attempts )); do
  set +e
  http_code=$(curl -sS -o /tmp/aegis-trigger.json -w '%{http_code}' \
    -X POST "$trigger_url" \
    -H "Authorization: Bearer $AEGIS_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$trigger_body" || echo 0)
  curl_exit=$?
  set -e

  if [[ "$http_code" =~ ^[235] ]] && (( curl_exit == 0 )); then
    trigger_status="$http_code"
    trigger_response=$(cat /tmp/aegis-trigger.json)
    break
  fi

  if [[ "$http_code" =~ ^(429|5[0-9][0-9])$ ]] || (( curl_exit != 0 )); then
    if (( attempt < max_attempts - 1 )); then
      delay="${backoff[$attempt]}"
      echo "WARN: trigger attempt $((attempt+1)) failed (http=$http_code curl=$curl_exit); retrying in ${delay}s" >&2
      sleep "$delay"
      attempt=$((attempt + 1))
      continue
    fi
  fi

  trigger_status="$http_code"
  trigger_response=$(cat /tmp/aegis-trigger.json 2>/dev/null || echo '{}')
  break
done

case "$trigger_status" in
  202)
    ;;
  401|403)
    echo "ERROR: Aegis trigger auth failed ($trigger_status): $trigger_response" >&2
    exit 1
    ;;
  404)
    echo "ERROR: Aegis source not found ($trigger_status): $trigger_response" >&2
    exit 1
    ;;
  409)
    echo "ERROR: Aegis source disabled ($trigger_status): $trigger_response" >&2
    exit 1
    ;;
  429)
    echo "ERROR: Aegis trigger rate limited; reduce CI scan frequency" >&2
    exit 1
    ;;
  *)
    echo "ERROR: Aegis trigger failed after retries ($trigger_status): $trigger_response" >&2
    exit 1
    ;;
esac

scan_id=$(echo "$trigger_response" | jq -r '.scan_id')
deduplicated=$(echo "$trigger_response" | jq -r '.deduplicated // false')
echo "Aegis scan_id=$scan_id deduplicated=$deduplicated"

if [[ "$WAIT" != "true" ]]; then
  exit 0
fi

start=$(date +%s)
status="queued"
summary='{}'

while true; do
  now=$(date +%s)
  if (( now - start > POLL_TIMEOUT )); then
    echo "WARN: Aegis scan still running after ${POLL_TIMEOUT}s; check $AEGIS_URL/api/v1/scans/$scan_id" >&2
    exit 0
  fi

  set +e
  status_response=$(curl -sS \
    -H "Authorization: Bearer $AEGIS_API_KEY" \
    "$AEGIS_URL/api/v1/scans/$scan_id" 2>/dev/null)
  curl_exit=$?
  set -e

  if (( curl_exit == 0 )); then
    status=$(echo "$status_response" | jq -r '.status')
    if [[ "$status" == "completed" || "$status" == "completed_with_merge_error" || "$status" == "failed" || "$status" == "cancelled" ]]; then
      summary="$status_response"
      break
    fi
  fi
  sleep 5
done

echo ""
echo "======== 🛡️ Aegis Security Scan ========"
echo "Status: $status"
echo "View in Aegis: $AEGIS_URL/api/v1/scans/$scan_id"
if echo "$summary" | jq -e '.finding_counts' >/dev/null; then
  echo ""
  echo "Findings:"
  echo "  🔴 High:   $(echo "$summary" | jq -r '.finding_counts.high // 0')"
  echo "  🟡 Medium: $(echo "$summary" | jq -r '.finding_counts.medium // 0')"
  echo "  ⚪ Low:    $(echo "$summary" | jq -r '.finding_counts.low // 0')"
fi
echo "========================================="

if [[ "$status" == "failed" ]]; then
  echo "ERROR: Aegis scan failed: $(echo "$summary" | jq -r '.error // "unknown"')" >&2
  exit 1
fi
if [[ "$status" == "cancelled" ]]; then
  echo "WARN: Aegis scan was cancelled (superseded by newer commit)" >&2
  exit 0
fi

high=$(echo "$summary" | jq -r '.finding_counts.high // 0')
medium=$(echo "$summary" | jq -r '.finding_counts.medium // 0')
low=$(echo "$summary" | jq -r '.finding_counts.low // 0')

case "$FAIL_ON" in
  high)
    if (( high > 0 )); then
      echo "ERROR: Found $high high-severity finding(s); failing per FAIL_ON=high" >&2
      exit 1
    fi
    ;;
  medium)
    if (( high > 0 || medium > 0 )); then
      echo "ERROR: Found findings ≥ medium severity; failing per FAIL_ON=medium" >&2
      exit 1
    fi
    ;;
  low)
    if (( high > 0 || medium > 0 || low > 0 )); then
      echo "ERROR: Found findings; failing per FAIL_ON=low" >&2
      exit 1
    fi
    ;;
  none|"")
    ;;
  *)
    echo "WARN: Unknown FAIL_ON value: $FAIL_ON (treated as none)" >&2
    ;;
esac

exit 0
