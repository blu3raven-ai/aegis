#!/usr/bin/env bash
# integrations/gitlab-component/scripts/trigger.sh
#
# DEVELOPER NOTE: This script is the source of truth for review purposes.
# The actual runtime logic is INLINED in templates/aegis-scan.yml. When you
# change this file, also update the inlined version in the YAML and bump
# the component version. They must stay in sync.
#
# To verify sync: diff this file against the `script:` block in the YAML
# (heredoc body). Both must be identical apart from the heredoc delimiters.

set -euo pipefail

# Environment variables (set by the GitLab component's input mapping):
#   AEGIS_URL, AEGIS_API_KEY, SOURCE_ID, WAIT, FAIL_ON, POLL_TIMEOUT_SECONDS

AEGIS_URL="${AEGIS_URL%/}"

COMMIT_SHA="${CI_COMMIT_SHA:-}"
BRANCH="${CI_COMMIT_REF_NAME:-}"
PR_NUMBER="${CI_MERGE_REQUEST_IID:-}"
RUN_ID="${CI_PIPELINE_ID:-}"

if [[ -z "$AEGIS_URL" || -z "$AEGIS_API_KEY" || -z "$SOURCE_ID" ]]; then
  echo "ERROR: aegis_url, aegis_api_key, and source_id are required" >&2
  exit 1
fi
if [[ -z "$COMMIT_SHA" ]]; then
  echo "ERROR: could not resolve commit SHA from GitLab CI context" >&2
  exit 1
fi

pr_payload="null"
if [[ -n "$PR_NUMBER" ]]; then
  pr_payload="$PR_NUMBER"
fi

trigger_body=$(jq -n \
  --arg commit_sha "$COMMIT_SHA" \
  --arg branch "$BRANCH" \
  --arg run_id "$RUN_ID" \
  --argjson pr_number "$pr_payload" \
  '{commit_sha: $commit_sha,
    branch: ($branch | select(. != "")),
    pr_number: $pr_number,
    trigger_metadata: {ci_provider: "gitlab", run_id: $run_id}}')

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

  if [[ "$http_code" =~ ^(2|3)[0-9][0-9]$ ]] && (( curl_exit == 0 )); then
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
    echo "ERROR: Aegis trigger rate limited" >&2
    exit 1
    ;;
  *)
    echo "ERROR: Aegis trigger failed ($trigger_status): $trigger_response" >&2
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

echo "Aegis scan status: $status"
if echo "$summary" | jq -e '.finding_counts' >/dev/null; then
  high=$(echo "$summary" | jq -r '.finding_counts.high // 0')
  medium=$(echo "$summary" | jq -r '.finding_counts.medium // 0')
  low=$(echo "$summary" | jq -r '.finding_counts.low // 0')
  echo "Findings: high=$high medium=$medium low=$low"
else
  high=0; medium=0; low=0
fi

if [[ "$status" == "failed" ]]; then
  echo "ERROR: Aegis scan failed: $(echo "$summary" | jq -r '.error // "unknown"')" >&2
  exit 1
fi
if [[ "$status" == "cancelled" ]]; then
  echo "WARN: Aegis scan cancelled (superseded by newer commit)" >&2
  exit 0
fi

case "$FAIL_ON" in
  high)
    if (( high > 0 )); then
      echo "ERROR: Found $high high-severity finding(s); failing per fail_on=high" >&2
      exit 1
    fi
    ;;
  medium)
    if (( high > 0 || medium > 0 )); then
      echo "ERROR: Found findings >= medium severity; failing per fail_on=medium" >&2
      exit 1
    fi
    ;;
  low)
    if (( high > 0 || medium > 0 || low > 0 )); then
      echo "ERROR: Found findings; failing per fail_on=low" >&2
      exit 1
    fi
    ;;
  none|"")
    ;;
  *)
    echo "WARN: Unknown fail_on value: $FAIL_ON (treated as none)" >&2
    ;;
esac

exit 0
