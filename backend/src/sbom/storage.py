"""Shared SBOM storage primitives — MinIO upload/download and component indexing."""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy import delete

from src.db.helpers import run_db
from src.db.models import SbomComponent
from src.sbom.licenses import category_rank, classify_licenses
from src.shared.object_store import get_s3_client

logger = logging.getLogger(__name__)

SBOM_BUCKET = "sboms"


def ensure_sbom_bucket() -> None:
    """Create the sboms bucket if it doesn't exist."""
    from botocore.exceptions import ClientError
    client = get_s3_client()
    try:
        client.head_bucket(Bucket=SBOM_BUCKET)
    except ClientError:
        client.create_bucket(Bucket=SBOM_BUCKET)
        logger.info("[+] Created S3 bucket: %s", SBOM_BUCKET)


def safe_s3_segment(value: str) -> str:
    """Sanitize a value for use in S3 keys — prevent path traversal."""
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", value.strip())
    while ".." in safe:
        safe = safe.replace("..", "_")
    return safe.lower()


def upload_to_minio(key: str, data: Any, bucket: str = SBOM_BUCKET) -> None:
    """Upload JSON data to the sboms bucket."""
    ensure_sbom_bucket()
    get_s3_client().put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(data).encode(),
        ContentType="application/json",
    )


def download_from_minio(key: str, bucket: str = SBOM_BUCKET) -> Any | None:
    """Download JSON data from the sboms bucket."""
    from botocore.exceptions import ClientError
    try:
        response = get_s3_client().get_object(Bucket=bucket, Key=key)
        raw = response["Body"].read()
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404", "NoSuchBucket"):
            return None
        raise
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        # A truncated/corrupt blob is treated as unreadable, not a 500.
        logger.warning("Unparseable SBOM blob at %s — treating as missing", key)
        return None


def _compute_direct_refs(sbom: dict[str, Any]) -> tuple[bool, set[str], set[str]]:
    """Resolve the CycloneDX root, its direct dependencies, and every bom-ref the
    graph mentions.

    Returns ``(graph_present, direct_refs, mentioned_refs)``. ``graph_present`` is
    False — making every component classify as unknown — when the SBOM lacks a
    root component bom-ref, lacks a dependency graph, describes a container/OS
    image (where "direct" has no meaning), has no dependency entry for the root,
    or the root declares no direct deps (no signal). ``direct_refs`` is the root
    entry's ``dependsOn`` set; ``mentioned_refs`` is every ref that appears in the
    graph (as a node or an edge target) — a component absent from it is an orphan
    the graph never connects, classified unknown rather than guessed transitive.

    All shape checks use isinstance so malformed-but-truthy SBOM input (e.g. a
    string ``metadata``) degrades to unknown instead of raising mid-ingest.
    """
    metadata = sbom.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    root = metadata.get("component")
    root = root if isinstance(root, dict) else {}
    root_ref = root.get("bom-ref")
    root_type = root.get("type")
    dep_graph = sbom.get("dependencies")
    dep_graph = dep_graph if isinstance(dep_graph, list) else []
    if not root_ref or not dep_graph or root_type in {"container", "operating-system"}:
        return False, set(), set()

    direct_refs: set[str] = set()
    mentioned: set[str] = set()
    root_found = False
    for dep in dep_graph:
        if not isinstance(dep, dict):
            continue
        ref = dep.get("ref")
        if isinstance(ref, str):
            mentioned.add(ref)
        depends_on = [r for r in (dep.get("dependsOn") or []) if isinstance(r, str)]
        mentioned.update(depends_on)
        if ref == root_ref:
            direct_refs = set(depends_on)
            root_found = True

    if not root_found or not direct_refs:
        # Root absent from the graph, or it declares zero direct deps — no
        # direct-ness signal, so everything is unknown.
        return False, set(), set()
    return True, direct_refs, mentioned


DECLARED_RANGE_PROPERTY = "aegis:declared_range"
DECLARED_SCOPE_PROPERTY = "aegis:declared_scope"
MANIFEST_PATH_PROPERTY = "aegis:declared_path"
MANIFEST_LINE_PROPERTY = "aegis:declared_line"
MANIFEST_SNIPPET_PROPERTY = "aegis:declared_snippet"
MANIFEST_SNIPPET_START_PROPERTY = "aegis:declared_snippet_start"
LAYER_DIGEST_PROPERTY = "aegis:layer_digest"
LAYER_INDEX_PROPERTY = "aegis:layer_index"


def _component_properties(comp: dict[str, Any]) -> dict[str, str]:
    """Flatten a component's CycloneDX ``properties`` into a name→value map.

    Guards every layer: ``properties`` may be missing or not a list, entries may
    not be dicts, and names/values may not be strings — anything malformed is
    dropped rather than raising mid-ingest. First value per name wins.
    """
    props = comp.get("properties")
    if not isinstance(props, list):
        return {}
    out: dict[str, str] = {}
    for prop in props:
        if not isinstance(prop, dict):
            continue
        name = prop.get("name")
        value = prop.get("value")
        if isinstance(name, str) and isinstance(value, str):
            out.setdefault(name, value)
    return out


def _as_int(value: str | None) -> int | None:
    """Parse a stamped integer property value, or None when absent/non-numeric."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def populate_components(
    org: str,
    resource_id: str,
    sbom: dict[str, Any],
    source_tool_fn: Callable[[dict[str, Any]], str | None] | None = None,
    asset_id: str | None = None,
    scanned_at: datetime | None = None,
) -> int:
    """Parse CycloneDX SBOM and upsert components into sbom_components table.

    asset_id is required after Plan D. The org/resource_id params are kept for
    backward-compat log messages only. ``scanned_at`` defaults to now; a
    re-index/backfill passes the asset's original scan time so re-classifying
    stored SBOMs doesn't reset every component's displayed scan timestamp.
    """
    if not asset_id:
        logger.warning(
            "[!] populate_components called without asset_id for %s/%s — skipping",
            org, resource_id,
        )
        return 0

    if not isinstance(sbom, dict):
        logger.warning(
            "[!] SBOM for %s/%s is not a JSON object (%s) — skipping",
            org, resource_id, type(sbom).__name__,
        )
        return 0

    components = sbom.get("components", [])
    if not isinstance(components, list):
        logger.warning(
            "[!] SBOM components for %s/%s is not a list (%s) — skipping",
            org, resource_id, type(components).__name__,
        )
        return 0
    if not components:
        logger.debug("[+] No components in SBOM for %s/%s — skipping", org, resource_id)
        return 0

    now = scanned_at or datetime.now(timezone.utc)
    rows: list[dict[str, Any]] = []
    skipped = 0

    # Direct vs transitive is classified from the dependency graph by each
    # component's own bom-ref (not its purl — they are distinct identity spaces).
    graph_present, direct_refs, mentioned_refs = _compute_direct_refs(sbom)

    MAX_PURL_LENGTH = 2048
    for comp in components:
        # A non-dict entry (malformed / non-CycloneDX blob) must skip just that
        # row — not abort indexing the whole asset, which would silently drop
        # its entire inventory and downstream SCA findings.
        if not isinstance(comp, dict):
            skipped += 1
            continue
        purl = comp.get("purl", "")
        if not purl or not isinstance(purl, str) or len(purl) > MAX_PURL_LENGTH:
            skipped += 1
            continue

        name = comp.get("name", "")
        version = comp.get("version", "")

        ecosystem = ""
        if purl.startswith("pkg:"):
            parts = purl[4:].split("/", 1)
            if parts:
                ecosystem = parts[0]

        source_tool = source_tool_fn(comp) if source_tool_fn else None
        lic = classify_licenses(comp.get("licenses") or [])
        props_map = _component_properties(comp)
        declared_range = props_map.get(DECLARED_RANGE_PROPERTY)
        scope = props_map.get(DECLARED_SCOPE_PROPERTY)
        manifest_path = props_map.get(MANIFEST_PATH_PROPERTY)
        manifest_line = _as_int(props_map.get(MANIFEST_LINE_PROPERTY))
        manifest_snippet = props_map.get(MANIFEST_SNIPPET_PROPERTY)
        manifest_snippet_start = _as_int(props_map.get(MANIFEST_SNIPPET_START_PROPERTY))
        layer_digest = props_map.get(LAYER_DIGEST_PROPERTY)
        layer_index = _as_int(props_map.get(LAYER_INDEX_PROPERTY))

        comp_ref = comp.get("bom-ref")
        if not graph_present or not comp_ref:
            is_direct: bool | None = None
        elif comp_ref in direct_refs:
            is_direct = True
        elif comp_ref in mentioned_refs:
            is_direct = False
        else:
            # Component present in components[] but referenced nowhere in the
            # graph — an orphan the graph never connects. Unknown, not transitive.
            is_direct = None

        rows.append({
            "asset_id": asset_id,
            "purl": purl,
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "source_tool": source_tool,
            "is_direct": is_direct,
            "license_expression": lic.expression,
            "license_category": lic.category,
            "declared_range": declared_range,
            "scope": scope,
            "manifest_path": manifest_path,
            "manifest_line": manifest_line,
            "manifest_snippet": manifest_snippet,
            "manifest_snippet_start": manifest_snippet_start,
            "layer_digest": layer_digest,
            "layer_index": layer_index,
            "scanned_at": now,
        })

    # Deduplicate by purl — SBOMs can list the same package multiple times. When
    # a purl repeats with differing directness, keep the strongest signal
    # (direct > transitive > unknown) so a package that is a direct dep anywhere
    # records direct. Likewise for license: a declared license beats no
    # declaration ("none"), and among declared the most restrictive wins —
    # otherwise a duplicate that declared a license the first row lacked is lost.
    _RANK = {True: 2, False: 1, None: 0}

    def _lic_key(row: dict[str, Any]) -> tuple[bool, int]:
        cat = row.get("license_category")
        return (cat is not None and cat != "none", category_rank(cat))

    by_purl: dict[str, dict[str, Any]] = {}
    for row in rows:
        existing = by_purl.get(row["purl"])
        if existing is None:
            by_purl[row["purl"]] = row
            continue
        if _RANK[row["is_direct"]] > _RANK[existing["is_direct"]]:
            existing["is_direct"] = row["is_direct"]
        if _lic_key(row) > _lic_key(existing):
            existing["license_expression"] = row["license_expression"]
            existing["license_category"] = row["license_category"]
        # Declared range + manifest location only live on the direct dep and are
        # stamped together; keep the first row that carried them (as one block, so
        # a range never pairs with another row's path) rather than lose it to a
        # duplicate that didn't.
        if existing.get("declared_range") is None and row.get("declared_range") is not None:
            for k in (
                "declared_range",
                "scope",
                "manifest_path",
                "manifest_line",
                "manifest_snippet",
                "manifest_snippet_start",
            ):
                existing[k] = row[k]
    unique_rows = list(by_purl.values())

    duplicates = len(rows) - len(unique_rows)
    if duplicates > 0:
        logger.info("[+] Deduplicated %d duplicate PURLs for %s/%s", duplicates, org, resource_id)
    if skipped > 0:
        logger.debug("[+] Skipped %d components without valid PURL for %s/%s", skipped, org, resource_id)

    async def _query(session):
        await session.execute(
            delete(SbomComponent).where(
                SbomComponent.asset_id == asset_id,
            )
        )
        session.add_all([SbomComponent(**row) for row in unique_rows])
        return len(unique_rows)

    try:
        count = run_db(_query)
    except Exception:
        logger.exception("[!] Failed to index components for %s/%s (%d rows)", org, resource_id, len(unique_rows))
        raise

    logger.info("[✓] Indexed %d components for %s/%s", count, org, resource_id)
    return count
