"""Split Finding.detail into lean JSONB and fat blob stored in MinIO."""
from __future__ import annotations

import json
import logging
from typing import Any

from botocore.exceptions import ClientError
from prometheus_client import Counter

from src.shared.encryption import decrypt, encrypt, is_encrypted
from src.shared.object_store import (
    _S3_BUCKET,
    download_bytes,
    get_s3_client,
    upload_bytes,
)

logger = logging.getLogger(__name__)

# Fat detail blobs hold the raw scanned-secret value (secretSnippet, raw.Secret)
# and the surrounding code window, so they are encrypted at rest under their own
# context. Legacy plaintext-JSON blobs are still read transparently (see below)
# until the encrypt backfill rewrites them.
_BLOB_CONTEXT = "finding_detail_blob"

# Prometheus counters for finding detail blob operations
finding_detail_blob_writes_total = Counter(
    "aegis_finding_detail_blob_writes_total",
    "Number of finding-detail blob writes to MinIO.",
)

finding_detail_blob_reads_total = Counter(
    "aegis_finding_detail_blob_reads_total",
    "Number of finding-detail blob reads from MinIO (cache misses).",
)

finding_detail_blob_read_misses_total = Counter(
    "aegis_finding_detail_blob_read_misses_total",
    "Number of finding-detail blob reads that found no object at the key.",
)

# Per-tool allowlist of keys that must stay in the JSONB column because
# application code filters/searches on them via SQL JSONB operators.
# Anything NOT listed here is considered fat and moved to MinIO.
LEAN_KEYS: dict[str, set[str]] = {
    "code_scanning": {
        "ruleId",
        "startLine",
        "endLine",
        "message",
        "category",
        "cwe",
        "owasp",
        "confidence",
        "language",
        "fileClass",
        "ruleIds",
    },
    "iac_scanning": {
        "checkId",
        "ruleName",
        "startLine",
        "resource",
        "severity",
        "guideline",
        "fingerprint",
    },
    "agent_scanning": {
        "checkId",
        "ruleName",
        "startLine",
        "resource",
        "severity",
        "guideline",
        "fingerprint",
    },
    "dependencies_scanning": {
        "ecosystem",
        "advisoryId",
        "vulnerableVersionRange",
        "patchedVersion",
        "manifestPath",
        "startLine",
        "currentVersion",
        "source",
        "scanner",
        "matchedBy",
        "cvssScore",
        "advisoryUrl",
        "matchSource",
    },
    "secret_scanning": {
        "organization",
        "secretIdentity",
        "fingerprint",
        "detector",
        "source",
        "repository",
        "line",
        "commit",
        "detectedAt",
    },
    "container_scanning": {
        "ecosystem",
        "advisoryId",
        "vulnerableVersionRange",
        "patchedVersion",
        "manifestPath",
        "imageName",
        "imageTag",
        "imageDigest",
        "layerCount",
        # layerIndex is lean so per-image "findings by layer" can aggregate in SQL.
        "layerIndex",
        "layerDigest",
        "sizeBytes",
        "baseOs",
        "currentVersion",
        "source",
        "scanner",
        "matchedBy",
        "fixState",
        "cvssScore",
        "advisoryUrl",
        "matchSource",
    },
}


def split_detail(tool: str, detail: dict) -> tuple[dict, dict]:
    """Split a detail dict into (lean, fat) based on the tool's LEAN_KEYS allowlist.

    Unknown tools keep everything lean so nothing is silently lost.
    Returns new dicts — the input is never mutated.
    """
    allowed = LEAN_KEYS.get(tool)
    if allowed is None:
        logger.warning("split_detail: unknown tool %r — keeping all keys lean", tool)
        return dict(detail), {}

    lean: dict[str, Any] = {}
    fat: dict[str, Any] = {}
    for key, value in detail.items():
        if key in allowed:
            lean[key] = value
        else:
            fat[key] = value
    return lean, fat


def build_blob_key(finding_id: int) -> str:
    """Return the stable MinIO key for a finding's fat detail blob."""
    return f"findings/{finding_id}/detail.json"


def put_detail_blob(finding_id: int, fat: dict) -> str | None:
    """Encrypt the fat dict and upload to MinIO; return the key, or None if empty."""
    if not fat:
        return None
    key = build_blob_key(finding_id)
    token = encrypt(json.dumps(fat, sort_keys=True), context=_BLOB_CONTEXT)
    upload_bytes(key, token.encode(), content_type="application/octet-stream")
    finding_detail_blob_writes_total.inc()
    return key


def _load_fat_blob(blob_key: str) -> dict | None:
    """Download + decode a fat blob. Handles both encrypted blobs and legacy
    plaintext-JSON blobs (written before at-rest encryption); returns None when
    the object is missing or can't be read."""
    raw = download_bytes(blob_key)
    if raw is None:
        return None
    try:
        text = raw.decode()
        if is_encrypted(text):
            # Lenient: an undecryptable blob degrades to lean detail rather than
            # 500-ing the finding view. The multi-root fallback means this only
            # trips if the encrypting root is truly gone.
            text = decrypt(text, context=_BLOB_CONTEXT)
            if not text:
                return None
        return json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def delete_detail_blob(key: str) -> None:
    """Best-effort delete of a fat detail blob; logs a warning on failure."""
    try:
        get_s3_client().delete_object(Bucket=_S3_BUCKET, Key=key)
    except ClientError as exc:
        logger.warning("delete_detail_blob: failed to delete %r: %s", key, exc)


def hydrate_detail(row: Any) -> dict:
    """Merge a Finding row's lean JSONB with its fat blob from MinIO.

    Result is cached on the row instance to avoid redundant S3 GETs.
    If the blob key is absent or the object is missing, returns the lean dict.
    """
    cached = getattr(row, "_hydrated_detail", None)
    if cached is not None:
        return cached

    lean = dict(row.detail)
    blob_key = getattr(row, "detail_blob_key", None)
    if blob_key is None:
        setattr(row, "_hydrated_detail", lean)
        return lean

    logger.debug("hydrate_detail issued MinIO GET for finding id=%s key=%s — should not happen on list-shaped paths", getattr(row, "id", "?"), blob_key)
    finding_detail_blob_reads_total.inc()
    fat = _load_fat_blob(blob_key)
    if fat is None:
        logger.warning("hydrate_detail: blob missing for key %r (finding id=%s)", blob_key, getattr(row, "id", "?"))
        finding_detail_blob_read_misses_total.inc()
        setattr(row, "_hydrated_detail", lean)
        return lean

    result = {**lean, **fat}
    setattr(row, "_hydrated_detail", result)
    return result
