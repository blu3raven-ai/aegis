#!/usr/bin/env bash
set -euo pipefail

source /scanner/shared/lib.sh
setup_output_dir

SCAN_MODE="${SCAN_MODE:-full}"
ORG_LABEL="${ORG_LABEL:-default}"
SCAN_PLATFORM="${SCAN_PLATFORM:-linux/amd64}"

# Configure registry auth for Syft
if [ -n "${REGISTRY_AUTHS:-}" ]; then
    mkdir -p "$HOME/.docker"
    python3 -c "
import json, os, sys
auths = json.loads(os.environ['REGISTRY_AUTHS'])
config = {'auths': {}}
for entry in auths:
    reg = entry.get('registry', '')
    tok = entry.get('token', '')
    usr = entry.get('username', '') or '_token'
    if reg and tok:
        config['auths'][reg] = {'username': usr, 'password': tok}
with open(os.path.join(os.environ['HOME'], '.docker', 'config.json'), 'w') as f:
    json.dump(config, f)
os.chmod(f.name, 0o600)
print(f'[+] Registry auth configured for {len(config[\"auths\"])} registries')
" || echo "[!] Failed to configure registry auth"
    # Prevent leaking credentials to child processes
    unset REGISTRY_AUTHS
fi

sanitize_name() {
    echo "$1" | sed 's/[^a-zA-Z0-9._-]/_/g'
}

validate_image_ref() {
    if ! [[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$ ]]; then
        echo "[!] Invalid image reference: $1"
        return 1
    fi
}

run_grype_match() {
    local sbom_path="$1"
    local output_path="$2"

    local grype_args=("sbom:${sbom_path}" "-o" "json" "--quiet")

    local grype_stderr
    grype_stderr=$(mktemp)
    if grype "${grype_args[@]}" > "$output_path" 2>"$grype_stderr"; then
        rm -f "$grype_stderr"
        return 0
    else
        local exit_code=$?
        # Exit 1 = vulnerabilities found (not an error)
        if [[ $exit_code -eq 1 ]]; then
            rm -f "$grype_stderr"
            return 0
        fi
        echo "[!] Grype failed (exit $exit_code) for $(basename "$sbom_path"): $(cat "$grype_stderr" 2>/dev/null | tail -3)" >&2
        rm -f "$output_path" "$grype_stderr"
        return $exit_code
    fi
}

_parse_image_ref() {
    local image_ref="$1"
    PARSED_REGISTRY="" PARSED_REPO="" PARSED_TAG=""
    if [[ "$image_ref" == *"/"*":"* ]]; then
        local no_tag="${image_ref%:*}"
        PARSED_TAG="${image_ref##*:}"
        PARSED_REGISTRY="${no_tag%%/*}"
        PARSED_REPO="${no_tag#*/}"
        return 0
    fi
    return 1  # Can't parse
}

_validate_registry_host() {
    local host="$1"

    # Block known dangerous hostnames
    case "$host" in
        localhost|*.localhost|metadata.google.internal|169.254.169.254)
            echo "[!] SSRF blocked: registry hostname '$host' is not allowed" >&2
            return 1
            ;;
    esac

    # Resolve hostname and check all IPs
    local resolved_ips
    resolved_ips=$(getent hosts "$host" 2>/dev/null | awk '{print $1}') || {
        # If DNS resolution fails, allow and let curl handle the error
        return 0
    }

    local ip
    for ip in $resolved_ips; do
        case "$ip" in
            # IPv4 private/reserved ranges
            10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*|127.*|169.254.*|0.*)
                echo "[!] SSRF blocked: registry '$host' resolves to private IP $ip" >&2
                return 1
                ;;
            # IPv6 loopback and private ranges
            ::1|fc00:*|fd00:*|fe80:*)
                echo "[!] SSRF blocked: registry '$host' resolves to private IP $ip" >&2
                return 1
                ;;
        esac
    done

    return 0
}

_get_registry_auth_header() {
    local registry="$1"
    if [ -f "$HOME/.docker/config.json" ]; then
        local b64
        b64=$(jq -r ".auths[\"$registry\"].password // empty" "$HOME/.docker/config.json" 2>/dev/null)
        if [ -n "$b64" ]; then
            local token_resp
            token_resp=$(curl -sf -u "_token:$b64" \
                "https://$registry/token?scope=repository:${PARSED_REPO}:pull&service=$registry" 2>/dev/null) || true
            local bearer
            bearer=$(echo "$token_resp" | jq -r '.token // empty' 2>/dev/null)
            if [ -n "$bearer" ]; then
                echo "Authorization: Bearer $bearer"
            else
                echo "Authorization: Basic $(echo -n "_token:$b64" | base64)"
            fi
        fi
    fi
}

get_registry_digest() {
    local image_ref="$1"
    _parse_image_ref "$image_ref" || return 1

    # SSRF protection: validate registry hostname before making any requests
    _validate_registry_host "$PARSED_REGISTRY" || return 1

    local auth_header
    auth_header=$(_get_registry_auth_header "$PARSED_REGISTRY")

    curl -sf --max-time 10 \
        ${auth_header:+-H "$auth_header"} \
        -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json" \
        --head \
        "https://$PARSED_REGISTRY/v2/$PARSED_REPO/manifests/$PARSED_TAG" 2>/dev/null \
        | grep -i "docker-content-digest" | tr -d '\r' | awk '{print $2}'
}

check_digest_changed() {
    local image_ref="$1"
    local prev_digest="$2"
    [ -z "$prev_digest" ] && return 0

    local digest
    digest=$(get_registry_digest "$image_ref")
    [ -z "$digest" ] && return 0
    [ "$digest" = "$prev_digest" ] && return 1
    return 0
}

scan_image() {
    local image_ref="$1"
    validate_image_ref "$image_ref" || return 1
    local safe_name
    safe_name="$(sanitize_name "$image_ref")"
    local target_dir="$OUTDIR/$safe_name"
    mkdir -p "$target_dir"

    log_scanning_image "$image_ref"

    # Skip unchanged images via digest comparison
    if [ -n "${PREVIOUS_DIGESTS:-}" ]; then
        local prev_digest
        prev_digest=$(IMAGE_REF="$image_ref" python3 -c "
import os, sys, json
d = json.loads(os.environ['PREVIOUS_DIGESTS'])
ref = os.environ['IMAGE_REF']
name = ref.rsplit(':', 1)[0] if ':' in ref else ref
for k, v in d.items():
    if k == ref or k == name:
        print(v); break
" 2>/dev/null)
        if [ -n "$prev_digest" ] && ! check_digest_changed "$image_ref" "$prev_digest"; then
            echo "[skip] $image_ref unchanged (digest match)"
            log_finished "$image_ref"
            return 0
        fi
    fi

    # Generate CycloneDX SBOM (registry: scheme pulls directly from registry)
    local syft_stderr
    syft_stderr=$(mktemp)
    if ! syft "registry:$image_ref" --platform "$SCAN_PLATFORM" -o cyclonedx-json \
        --parallelism 2 \
        > "$target_dir/sbom.cdx.json" 2>"$syft_stderr"; then
        echo "[!] Syft failed for $image_ref: $(tail -3 "$syft_stderr" 2>/dev/null)"
        rm -f "$syft_stderr"
        log_finished "$image_ref"
        return 1
    fi
    rm -f "$syft_stderr"

    if [ "$SCAN_MODE" = "sbom_only" ]; then
        register_output "$target_dir/sbom.cdx.json" "$safe_name"
        log_finished "$image_ref"
        return 0
    fi

    run_grype_match "$target_dir/sbom.cdx.json" "$target_dir/findings.json" || true

    # Record digest for skip-unchanged optimization; prefer SBOM hash, fall back to registry
    local digest=""
    digest=$(jq -r '
      (.metadata.component.hashes // [] | map(select(.alg == "SHA-256")) | .[0].content // empty) //
      empty
    ' "$target_dir/sbom.cdx.json" 2>/dev/null)
    if [[ -n "$digest" && "$digest" != "null" ]]; then
        echo "sha256:$digest" > "$target_dir/digest.txt"
    else
        get_registry_digest "$image_ref" > "$target_dir/digest.txt" 2>/dev/null || true
    fi

    register_output "$target_dir/sbom.cdx.json" "$safe_name"
    register_output "$target_dir/findings.json" "$safe_name"
    register_output "$target_dir/digest.txt" "$safe_name"

    log_finished "$image_ref"
}

scan_advisories_only() {
    local image_ref="$1"
    validate_image_ref "$image_ref" || return 1
    local safe_name
    safe_name="$(sanitize_name "$image_ref")"
    local target_dir="$OUTDIR/$safe_name"
    mkdir -p "$target_dir"

    log_scanning_image "$image_ref"

    # Download stored SBOM from object storage
    local s3_key
    s3_key="$(echo "$image_ref" | sed 's/[/:]/_/g')"
    local sbom_path="$target_dir/sbom.cdx.json"

    if [ -n "${S3_ENDPOINT:-}" ]; then
        SBOM_S3_KEY="$s3_key" SBOM_OUTPUT_PATH="$sbom_path" python3 -c "
import os
from minio import Minio

endpoint = os.environ['S3_ENDPOINT']
access_key = os.environ['S3_ACCESS_KEY']
secret_key = os.environ['S3_SECRET_KEY']
bucket = os.environ.get('S3_BUCKET', 'sboms')
org = os.environ['ORG_LABEL']
s3_key = os.environ['SBOM_S3_KEY']
output_path = os.environ['SBOM_OUTPUT_PATH']

host = endpoint.replace('http://', '').replace('https://', '')
client = Minio(host, access_key=access_key, secret_key=secret_key,
               secure=endpoint.startswith('https'))
client.fget_object(bucket, f'{org}/{s3_key}/sbom.cdx.json', output_path)
" 2>/dev/null || {
            echo "[!] Failed to download SBOM for $image_ref"
            log_finished "$image_ref"
            return 1
        }
    fi

    if [ ! -f "$sbom_path" ]; then
        echo "[!] No stored SBOM found for $image_ref"
        log_finished "$image_ref"
        return 1
    fi

    run_grype_match "$sbom_path" "$target_dir/findings.json" || true
    register_output "$target_dir/findings.json" "$safe_name"

    log_finished "$image_ref"
}

# Main

echo "[+] Checking Grype vulnerability database..."
if ! grype db check >/dev/null 2>&1; then
    echo "[+] Updating Grype vulnerability database..."
    if grype db update 2>&1; then
        echo "[✓] Grype DB updated successfully"
    else
        echo "[!] Grype DB update failed — scanning may produce incomplete results"
    fi
else
    echo "[✓] Grype DB is current"
fi

IFS=',' read -ra IMAGES <<< "${DOCKER_IMAGES:-}"

if [ ${#IMAGES[@]} -eq 0 ]; then
    echo "[!] No images provided via DOCKER_IMAGES"
    exit 1
fi

echo "[+] ${#IMAGES[@]} images to scan (mode: $SCAN_MODE)"

if [ "$SCAN_MODE" = "advisories_only" ]; then
    export -f scan_advisories_only sanitize_name validate_image_ref run_grype_match register_output log_scanning_image log_finished
    export OUTDIR SCAN_MODE ORG_LABEL SCAN_PLATFORM
    printf '%s\n' "${IMAGES[@]}" | parallel -j "$CONCURRENCY" scan_advisories_only || true
else
    export -f scan_image sanitize_name validate_image_ref run_grype_match _parse_image_ref _validate_registry_host _get_registry_auth_header get_registry_digest check_digest_changed register_output log_scanning_image log_finished
    export OUTDIR SCAN_MODE SCAN_PLATFORM PREVIOUS_DIGESTS
    printf '%s\n' "${IMAGES[@]}" | parallel -j "$CONCURRENCY" scan_image || true
fi

# Normalization
for dir in "$OUTDIR"/*/; do
    findings_json="$dir/findings.json"
    sbom_json="$dir/sbom.cdx.json"
    if [ -f "$findings_json" ] && [ -f "$sbom_json" ]; then
        image_ref=$(jq -r '.metadata.component.name // "unknown"' "$sbom_json" 2>/dev/null)
        image_digest=$(cat "$dir/digest.txt" 2>/dev/null || echo "")
        python3 /scanner/scripts/normalize-container.py \
            "$findings_json" \
            --org "$ORG_LABEL" \
            --image-ref "$image_ref" \
            --image-digest "$image_digest" \
            >> "$OUTDIR/findings.jsonl"
    fi
done

sbom_count=$(find "$OUTDIR" -name "sbom.cdx.json" -size +0 2>/dev/null | wc -l | tr -d ' ')
if [ "$sbom_count" -eq 0 ]; then
    echo "[!] No images were successfully scanned — all Syft invocations failed"
    exit 1
fi
echo "[+] $sbom_count/${#IMAGES[@]} images produced SBOMs"

python3 /scanner/manifest.py "$OUTDIR"

echo "[✓] Scan complete"
