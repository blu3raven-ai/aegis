#!/usr/bin/env bash
set -euo pipefail

# Required env vars (set by action.yml):
#   INPUT_AEGIS_URL, INPUT_API_KEY, INPUT_SOURCE_ID
#   INPUT_WAIT, INPUT_FAIL_ON, INPUT_POLL_TIMEOUT_SECONDS
#   GH_COMMIT_SHA, GH_BRANCH, GH_PR_NUMBER, GH_RUN_ID

AEGIS_URL="${INPUT_AEGIS_URL%/}"
SOURCE_ID="$INPUT_SOURCE_ID"
WAIT="$INPUT_WAIT"
FAIL_ON="$INPUT_FAIL_ON"
POLL_TIMEOUT="$INPUT_POLL_TIMEOUT_SECONDS"

if [[ -z "${INPUT_AEGIS_URL:-}" || -z "${INPUT_API_KEY:-}" || -z "${INPUT_SOURCE_ID:-}" ]]; then
  echo "::error::aegis-url, api-key, and source-id are required" >&2
  exit 1
fi
if [[ -z "${GH_COMMIT_SHA:-}" ]]; then
  echo "::error::could not resolve commit SHA from GitHub context" >&2
  exit 1
fi

trigger_body=$(jq -n \
  --arg commit_sha "$GH_COMMIT_SHA" \
  --arg branch "${GH_BRANCH:-}" \
  --arg run_id "${GH_RUN_ID:-}" \
  --argjson pr_number "${GH_PR_NUMBER:-null}" \
  '{commit_sha: $commit_sha,
    branch: ($branch | select(. != "")),
    pr_number: $pr_number,
    trigger_metadata: {ci_provider: "github_actions", run_id: $run_id}}')

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
    -H "Authorization: Bearer $INPUT_API_KEY" \
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
      echo "::warning::trigger attempt $((attempt+1)) failed (http=$http_code curl=$curl_exit); retrying in ${delay}s" >&2
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
    echo "::error::Aegis trigger auth failed ($trigger_status): $trigger_response" >&2
    exit 1
    ;;
  404)
    echo "::error::Aegis source not found ($trigger_status): $trigger_response" >&2
    exit 1
    ;;
  409)
    echo "::error::Aegis source disabled ($trigger_status): $trigger_response" >&2
    exit 1
    ;;
  429)
    echo "::error::Aegis trigger rate limited; please reduce CI scan frequency" >&2
    exit 1
    ;;
  *)
    echo "::error::Aegis trigger failed after retries ($trigger_status): $trigger_response" >&2
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
    echo "::warning::Aegis scan still running after ${POLL_TIMEOUT}s; check $AEGIS_URL/api/v1/scans/$scan_id" >&2
    exit 0
  fi

  set +e
  status_response=$(curl -sS \
    -H "Authorization: Bearer $INPUT_API_KEY" \
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

{
  echo "# 🛡️ Aegis Security Scan"
  echo ""
  echo "Status: **$status**"
  echo ""
  echo "View in Aegis: $AEGIS_URL/api/v1/scans/$scan_id"
  echo ""
  if echo "$summary" | jq -e '.finding_counts' >/dev/null; then
    echo "| Severity | Count |"
    echo "|---|---|"
    echo "| 🔴 High | $(echo "$summary" | jq -r '.finding_counts.high // 0') |"
    echo "| 🟡 Medium | $(echo "$summary" | jq -r '.finding_counts.medium // 0') |"
    echo "| ⚪ Low | $(echo "$summary" | jq -r '.finding_counts.low // 0') |"
  fi
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

if [[ "$status" == "failed" ]]; then
  echo "::error::Aegis scan failed: $(echo "$summary" | jq -r '.error // "unknown"')"
  exit 1
fi
if [[ "$status" == "cancelled" ]]; then
  echo "::warning::Aegis scan was cancelled (superseded by newer commit)"
  exit 0
fi

high=$(echo "$summary" | jq -r '.finding_counts.high // 0')
medium=$(echo "$summary" | jq -r '.finding_counts.medium // 0')
low=$(echo "$summary" | jq -r '.finding_counts.low // 0')

case "$FAIL_ON" in
  high)
    if (( high > 0 )); then
      echo "::error::Found $high high-severity finding(s); failing per fail-on=high"
      exit 1
    fi
    ;;
  medium)
    if (( high > 0 || medium > 0 )); then
      echo "::error::Found findings ≥ medium severity; failing per fail-on=medium"
      exit 1
    fi
    ;;
  low)
    if (( high > 0 || medium > 0 || low > 0 )); then
      echo "::error::Found findings; failing per fail-on=low"
      exit 1
    fi
    ;;
  none|"")
    ;;
  *)
    echo "::warning::Unknown fail-on value: $FAIL_ON (treated as none)"
    ;;
esac

exit 0
