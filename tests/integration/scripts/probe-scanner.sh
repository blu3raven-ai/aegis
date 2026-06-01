#!/usr/bin/env bash
# Boot a single scanner container in http_api mode and assert its endpoints
# work end-to-end. Used by .github/workflows/scanner-http-integration.yml.
#
# Usage: probe-scanner.sh <scanner_type> <image>
#   scanner_type: dependencies | container | code-scanning | secrets
#   image:        local image tag built earlier in the workflow
#
# Environment:
#   HTTP_API_PORT          host port to bind (default 8081)
#   WORKSPACE_ROOT         host dir to mount at /workspace (required for
#                          dependencies / code-scanning / secrets)
#   DEPS_FIXTURE_NAME      subdir name inside WORKSPACE_ROOT (default
#                          sample-python-repo)
#   SECRETS_FIXTURE_NAME   subdir name inside WORKSPACE_ROOT (default
#                          sample-secrets-repo)

set -euo pipefail

SCANNER_TYPE="${1:?scanner type required}"
IMAGE="${2:?image required}"
HTTP_API_PORT="${HTTP_API_PORT:-8081}"
DEPS_FIXTURE_NAME="${DEPS_FIXTURE_NAME:-sample-python-repo}"
SECRETS_FIXTURE_NAME="${SECRETS_FIXTURE_NAME:-sample-secrets-repo}"

CONTAINER_NAME="aegis-int-${SCANNER_TYPE}-$$"

cleanup() {
  local rc=$?
  if [ "${rc}" -ne 0 ]; then
    echo "::group::container logs (${CONTAINER_NAME})"
    docker logs "${CONTAINER_NAME}" 2>&1 || true
    echo "::endgroup::"
  fi
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  exit "${rc}"
}
trap cleanup EXIT

DOCKER_RUN_ARGS=(
  --rm -d
  --name "${CONTAINER_NAME}"
  -e "SCANNER_RUNTIME_MODE=http_api"
  -e "HTTP_API_PORT=${HTTP_API_PORT}"
  -p "${HTTP_API_PORT}:${HTTP_API_PORT}"
)

case "${SCANNER_TYPE}" in
  dependencies|code-scanning|secrets)
    if [ -z "${WORKSPACE_ROOT:-}" ]; then
      echo "WORKSPACE_ROOT required for ${SCANNER_TYPE}" >&2
      exit 2
    fi
    DOCKER_RUN_ARGS+=(-v "${WORKSPACE_ROOT}:/workspace:ro")
    ;;
esac

echo "starting ${SCANNER_TYPE} container..."
docker run "${DOCKER_RUN_ARGS[@]}" "${IMAGE}" >/dev/null

BASE_URL="http://127.0.0.1:${HTTP_API_PORT}"

echo "waiting for /v1/health..."
for i in $(seq 1 30); do
  if curl -fsS "${BASE_URL}/v1/health" >/dev/null 2>&1; then
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "scanner did not become healthy within 30s" >&2
    exit 1
  fi
  sleep 1
done

echo "checking /v1/version..."
VERSION_JSON="$(curl -fsS "${BASE_URL}/v1/version")"
echo "version response: ${VERSION_JSON}"
if [ "${VERSION_JSON}" = "{}" ] || [ -z "${VERSION_JSON}" ]; then
  echo "empty /v1/version response" >&2
  exit 1
fi

case "${SCANNER_TYPE}" in
  dependencies)
    echo "POST /v1/sbom..."
    SBOM_RESP="$(curl -fsS -X POST -H 'Content-Type: application/json' \
      -d "{\"checkout_ref\":\"workspace://${DEPS_FIXTURE_NAME}\"}" \
      "${BASE_URL}/v1/sbom")"
    SBOM_FRAGMENT="$(printf '%s' "${SBOM_RESP}" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(json.dumps(d["sbom"]))')"
    echo "POST /v1/match..."
    MATCH_RESP="$(curl -fsS -X POST -H 'Content-Type: application/json' \
      --data-binary @- "${BASE_URL}/v1/match" <<EOF
{"sbom": ${SBOM_FRAGMENT}}
EOF
)"
    python3 -c 'import json,sys;d=json.loads(sys.argv[1]);assert isinstance(d.get("matches"),list),d' "${MATCH_RESP}"
    ;;

  container)
    echo "POST /v1/sbom (alpine:3.20)..."
    SBOM_RESP="$(curl -fsS -X POST -H 'Content-Type: application/json' \
      -d '{"image_pull_ref":"docker.io/library/alpine:3.20"}' \
      "${BASE_URL}/v1/sbom")"
    python3 -c 'import json,sys;d=json.loads(sys.argv[1]);c=d["sbom"].get("components",[]);assert c,"empty components"' "${SBOM_RESP}"
    ;;

  code-scanning)
    echo "POST /v1/scan..."
    SCAN_RESP="$(curl -fsS -X POST -H 'Content-Type: application/json' \
      -d "{\"checkout_ref\":\"workspace://${DEPS_FIXTURE_NAME}\"}" \
      "${BASE_URL}/v1/scan")"
    python3 -c 'import json,sys;d=json.loads(sys.argv[1]);r=d.get("results",[]);assert r,"no SAST findings"' "${SCAN_RESP}"
    ;;

  secrets)
    SINCE="$(docker run --rm -v "${WORKSPACE_ROOT}/${SECRETS_FIXTURE_NAME}:/repo:ro" \
      alpine/git -C /repo rev-list --max-parents=0 HEAD | head -1 | tr -d '[:space:]')"
    if [ -z "${SINCE}" ]; then
      echo "could not resolve initial commit sha" >&2
      exit 1
    fi
    echo "POST /v1/scan (since_commit=${SINCE})..."
    SCAN_RESP="$(curl -fsS -X POST -H 'Content-Type: application/json' \
      -d "{\"checkout_ref\":\"workspace://${SECRETS_FIXTURE_NAME}\",\"since_commit\":\"${SINCE}\"}" \
      "${BASE_URL}/v1/scan")"
    python3 -c 'import json,sys;d=json.loads(sys.argv[1]);f=d.get("findings",[]);assert f,"no secrets findings"' "${SCAN_RESP}"
    ;;

  *)
    echo "unknown scanner type: ${SCANNER_TYPE}" >&2
    exit 2
    ;;
esac

echo "${SCANNER_TYPE}: probe ok"
