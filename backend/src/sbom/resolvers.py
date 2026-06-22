"""GraphQL resolvers for SBOM component search, history, and diff."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Annotated, Any, Optional, Union

import strawberry
from sqlalchemy import func, select, or_, and_

from src.db.helpers import run_db
from src.db.models import Asset, SbomComponent, Sbom
from src.assets.refs import owner_from_external_ref
from src.sbom.diff import diff_sboms
from src.shared.object_store import list_objects, download_json
from src.sbom.storage import download_from_minio

from src.graphql.limits import clamp_per_page

logger = logging.getLogger(__name__)

MAX_BULK_ITEMS = 500


def _escape_like(s: str) -> str:
    """Escape LIKE metacharacters so user input is treated as literal text."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _safe_owner_from_ref(external_ref: str | None) -> str:
    """Return owner segment of external_ref, or empty string on failure.

    Used at GraphQL response time where raising on an unrecognized ref
    would break a paginated list response.
    """
    if not external_ref:
        return ""
    try:
        return owner_from_external_ref(external_ref)
    except ValueError:
        return ""


@strawberry.type
class SbomComponentNode:
    name: str
    version: str
    ecosystem: str
    purl: str
    repo: str
    org: str
    source_tool: Optional[str]
    scanned_at: str


@strawberry.type
class SbomComponentsConnection:
    items: list[SbomComponentNode]
    total: int
    page: int
    per_page: int
    total_pages: int


@strawberry.type
class SbomFilterOptions:
    ecosystems: list[str]
    repositories: list[str]
    sources: list[str]


@strawberry.type
class SbomCrossReference:
    repo: str
    org: str
    version: str
    source_tool: Optional[str]
    scanned_at: str


@strawberry.type
class SbomBulkMatch:
    query: str
    found: bool
    name: str
    version: str
    ecosystem: str
    purl: str
    repos: list[str]


def _parse_version_tuple(v: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple of ints."""
    parts = re.split(r"[.\-+]", v)
    result: list[int] = []
    for p in parts:
        digits = re.match(r"(\d+)", p)
        if digits:
            result.append(int(digits.group(1)))
        else:
            break
    return tuple(result) if result else (0,)


def sbom_search(
    *,
    search: Optional[str] = None,
    ecosystems: Optional[list[str]] = None,
    source: Optional[str] = None,
    repos: Optional[list[str]] = None,
    version_op: Optional[str] = None,
    version_value: Optional[str] = None,
    version_value_end: Optional[str] = None,
    filter_logic: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
    info_context: dict,
) -> SbomComponentsConnection:
    """Search SBOM components across all user assets."""
    per_page = clamp_per_page(per_page)
    search = (search or "")[:200] or None
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids:
        return SbomComponentsConnection(items=[], total=0, page=page, per_page=per_page, total_pages=0)

    use_or = filter_logic == "or"

    async def _query(session):
        # After Plan D, SbomComponent.asset_id is available; scope directly.
        # Joins Asset so repo/org display info is available per row.
        allowed_sbom_ids = select(Sbom.id).where(Sbom.asset_id.in_(asset_ids)).scalar_subquery()
        base = (
            select(SbomComponent, Asset)
            .join(Sbom, SbomComponent.asset_id == Sbom.asset_id)
            .join(Asset, Asset.id == SbomComponent.asset_id)
            .where(Sbom.id.in_(allowed_sbom_ids))
        )

        if search:
            term = f"%{_escape_like(search)}%"
            base = base.where(
                or_(
                    SbomComponent.name.ilike(term),
                    SbomComponent.purl.ilike(term),
                    SbomComponent.version.ilike(term),
                )
            )

        # Build group conditions for AND/OR toggle
        group_conditions = []
        if ecosystems:
            group_conditions.append(SbomComponent.ecosystem.in_([e.lower() for e in ecosystems]))
        if source:
            if source == "dependencies":
                group_conditions.append(SbomComponent.source_tool.in_(["syft", "cdxgen", "both"]))
            elif source == "containers":
                group_conditions.append(SbomComponent.source_tool.is_(None))
        if repos:
            # `repos` are human-readable display_names (e.g. "acme/foo");
            # resolve to asset_ids and intersect with the SBOM scope.
            group_conditions.append(
                SbomComponent.asset_id.in_(
                    select(Asset.id).where(Asset.display_name.in_(repos))
                )
            )

        if group_conditions:
            combiner = or_ if use_or else and_
            base = base.where(combiner(*group_conditions))

        count_q = select(func.count()).select_from(base.subquery())
        total = (await session.execute(count_q)).scalar() or 0

        offset = (page - 1) * per_page
        rows = (
            await session.execute(
                base.order_by(SbomComponent.name, SbomComponent.version)
                .offset(offset)
                .limit(per_page)
            )
        ).all()

        # Apply version filtering in Python (semver comparison isn't reliable in SQL)
        if version_op and version_value:
            target = _parse_version_tuple(version_value)
            target_end = _parse_version_tuple(version_value_end) if version_value_end else None

            def _version_match(comp):
                v = _parse_version_tuple(comp.version)
                if version_op == "eq":
                    return v == target
                if version_op == "gte":
                    return v >= target
                if version_op == "lte":
                    return v <= target
                if version_op == "range" and target_end:
                    return target <= v <= target_end
                return False

            # For version filtering we need to re-count by fetching all matching rows
            # and filtering. For simplicity, we do full scan with version filter.
            all_rows = (
                await session.execute(
                    base.order_by(SbomComponent.name, SbomComponent.version)
                )
            ).all()

            all_filtered = [(r, a) for r, a in all_rows if _version_match(r)]
            total = len(all_filtered)
            rows = all_filtered[offset:offset + per_page]

        items = [
            SbomComponentNode(
                name=r.name,
                version=r.version,
                ecosystem=r.ecosystem,
                purl=r.purl,
                repo=a.display_name,
                org=_safe_owner_from_ref(a.external_ref),
                source_tool=r.source_tool,
                scanned_at=r.scanned_at.isoformat() if r.scanned_at else "",
            )
            for r, a in rows
        ]

        total_pages = (total + per_page - 1) // per_page if per_page > 0 else 0
        return SbomComponentsConnection(
            items=items, total=total, page=page, per_page=per_page, total_pages=total_pages
        )

    return run_db(_query)


def sbom_filter_options(*, info_context: dict) -> SbomFilterOptions:
    """Return available filter values for SBOM search."""
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids:
        return SbomFilterOptions(ecosystems=[], repositories=[], sources=[])

    async def _query(session):
        # After Plan D, SbomComponent.asset_id is available; scope directly.
        allowed_sbom_ids = select(Sbom.id).where(Sbom.asset_id.in_(asset_ids)).scalar_subquery()
        asset_join = SbomComponent.asset_id == Sbom.asset_id

        eco_q = (
            select(SbomComponent.ecosystem)
            .join(Sbom, asset_join)
            .where(Sbom.id.in_(allowed_sbom_ids), SbomComponent.ecosystem != "")
            .distinct()
            .order_by(SbomComponent.ecosystem)
        )
        ecosystems = [r[0] for r in (await session.execute(eco_q)).all()]

        sources = ["dependencies", "containers"]
        repo_q = (
            select(Asset.display_name)
            .where(Asset.id.in_(asset_ids))
            .distinct()
            .order_by(Asset.display_name)
        )
        repositories = [r[0] for r in (await session.execute(repo_q)).all() if r[0]]

        return SbomFilterOptions(ecosystems=ecosystems, repositories=repositories, sources=sources)

    return run_db(_query)


def sbom_cross_references(
    *, purl: str, info_context: dict
) -> list[SbomCrossReference]:
    """Find all repos/images that contain a specific package (by PURL)."""
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids:
        return []

    async def _query(session):
        # After Plan D, SbomComponent.asset_id is available; scope directly.
        allowed_sbom_ids = select(Sbom.id).where(Sbom.asset_id.in_(asset_ids)).scalar_subquery()
        q = (
            select(SbomComponent, Asset)
            .join(Sbom, SbomComponent.asset_id == Sbom.asset_id)
            .join(Asset, Asset.id == SbomComponent.asset_id)
            .where(
                Sbom.id.in_(allowed_sbom_ids),
                SbomComponent.purl == purl,
            )
            .order_by(SbomComponent.asset_id)
        )
        rows = (await session.execute(q)).all()
        return [
            SbomCrossReference(
                repo=a.display_name,
                org=_safe_owner_from_ref(a.external_ref),
                version=r.version,
                source_tool=r.source_tool,
                scanned_at=r.scanned_at.isoformat() if r.scanned_at else "",
            )
            for r, a in rows
        ]

    return run_db(_query)


def sbom_bulk_lookup(
    *, queries: list[str], info_context: dict
) -> list[SbomBulkMatch]:
    """Check which packages from a list exist in the estate."""
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids or not queries:
        return []

    clean = [q.strip() for q in queries[:MAX_BULK_ITEMS] if q.strip()]
    if not clean:
        return []

    async def _query(session):
        # After Plan D, SbomComponent.asset_id is available; scope directly.
        allowed_sbom_ids = select(Sbom.id).where(Sbom.asset_id.in_(asset_ids)).scalar_subquery()
        asset_join = SbomComponent.asset_id == Sbom.asset_id
        asset_scope = Sbom.id.in_(allowed_sbom_ids)
        results: list[SbomBulkMatch] = []

        for q in clean:
            conditions = [asset_scope]

            if q.startswith("pkg:"):
                conditions.append(SbomComponent.purl == q)
            else:
                escaped = _escape_like(q)
                conditions.append(
                    or_(
                        SbomComponent.name.ilike(escaped),
                        SbomComponent.name.ilike(f"%/{escaped}"),
                    )
                )

            rows = (
                await session.execute(
                    select(SbomComponent, Asset)
                    .join(Sbom, asset_join)
                    .join(Asset, Asset.id == SbomComponent.asset_id)
                    .where(and_(*conditions))
                    .limit(100)
                )
            ).all()

            if rows:
                repos: list[str] = sorted({a.display_name for _, a in rows if a.display_name})
                first = rows[0][0]
                results.append(SbomBulkMatch(
                    query=q,
                    found=True,
                    name=first.name,
                    version=first.version,
                    ecosystem=first.ecosystem,
                    purl=first.purl,
                    repos=repos,
                ))
            else:
                results.append(SbomBulkMatch(
                    query=q,
                    found=False,
                    name="",
                    version="",
                    ecosystem="",
                    purl="",
                    repos=[],
                ))

        return results

    return run_db(_query)


# ── SBOM run history + diff ──────────────────────────────────────────────────


@strawberry.type
class SbomHistoryEntry:
    run_id: str
    created_at: Optional[str]
    key: str


@strawberry.type
class SbomDiffComponent:
    name: str
    version: str
    purl: str
    type: str


@strawberry.type
class SbomVersionChange:
    name: str
    purl: str
    from_version: Optional[str]
    to_version: Optional[str]


@strawberry.type
class SbomDiffResult:
    added: list[SbomDiffComponent]
    removed: list[SbomDiffComponent]
    version_changed: list[SbomVersionChange]
    unchanged_count: int


@strawberry.type
class SbomDiffError:
    message: str
    code: str


SbomDiffOrError = Annotated[
    Union[SbomDiffResult, SbomDiffError],
    strawberry.union("SbomDiffOrError"),
]


_MAX_HISTORY_LIMIT = 100
_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_\-][A-Za-z0-9._\-]*$")
_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-][A-Za-z0-9._\-]*$")
_IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[A-Fa-f0-9]{64}$")


def _safe_segment(s: str) -> bool:
    """Return True iff ``s`` is a safe path segment.

    Rejects empty strings, dot/dotdot segments, leading dots, and any
    character outside the allowlist. The leading-dot rule blocks the
    classic ``.git`` / ``..foo`` traversal vectors before the value can
    flow into MinIO prefix concatenation.
    """
    if s in (".", ".."):
        return False
    if ".." in s:
        return False
    return bool(_SEGMENT_PATTERN.match(s))


def _validate_repo_id(repo_id: str) -> tuple[str, str] | None:
    """Return (owner, name) if repo_id is a safe owner/name pair, else None.

    Input flows into a MinIO prefix concatenation, so the allowlist must
    be strict — any traversal or unexpected character returns None and
    the caller short-circuits to a uniform "not found" response.
    """
    parts = repo_id.split("/")
    if len(parts) != 2:
        return None
    owner, name = parts
    if not _safe_segment(owner) or not _safe_segment(name):
        return None
    return owner, name


def _safe_run_id(run_id: str) -> bool:
    return _safe_segment(run_id) and bool(_RUN_ID_PATTERN.match(run_id))


def _repo_in_scope_async(repo_id: str, asset_ids: list[str]) -> bool:
    if not asset_ids:
        return False

    async def _query(session):
        result = await session.execute(
            select(Asset.id)
            .where(Asset.display_name == repo_id)
            .where(Asset.type == "repo")
            .where(Asset.id.in_(asset_ids))
            .limit(1)
        )
        return result.scalar_one_or_none()

    return run_db(_query) is not None


def _run_id_to_iso(run_id: str) -> str | None:
    if run_id.startswith("auto-"):
        try:
            ms = int(run_id[5:])
            return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            pass
    return None


def sbom_history(
    *,
    repo: str,
    limit: int = 10,
    info_context: dict,
) -> list[SbomHistoryEntry]:
    """List historical SBOM run entries for a repository.

    Returns at most ``limit`` entries (clamped to 1..100), newest first.
    Out-of-scope or non-existent repos return an empty list — never reveal
    existence to a viewer who cannot see the asset.
    """
    asset_ids = info_context.get("asset_ids", [])
    limit = max(1, min(_MAX_HISTORY_LIMIT, limit))

    parsed = _validate_repo_id(repo)
    if parsed is None:
        return []
    if not _repo_in_scope_async(repo, asset_ids):
        return []

    owner, name = parsed
    prefix = f"dependencies_scanning/{owner}/"
    suffix = f"/{name}/sbom.cdx.json"
    keys = sorted(
        [k for k in list_objects(prefix) if k.endswith(suffix)],
        reverse=True,
    )[:limit]

    entries: list[SbomHistoryEntry] = []
    for key in keys:
        parts = key.split("/")
        run_id = parts[2] if len(parts) >= 4 else ""
        entries.append(SbomHistoryEntry(
            run_id=run_id,
            created_at=_run_id_to_iso(run_id),
            key=key,
        ))
    return entries


def _component_to_diff(c: dict[str, Any]) -> SbomDiffComponent:
    return SbomDiffComponent(
        name=str(c.get("name") or ""),
        version=str(c.get("version") or ""),
        purl=str(c.get("purl") or ""),
        type=str(c.get("type") or ""),
    )


def _fetch_container_sbom_by_digest(
    image_digest: str,
) -> tuple[dict[str, Any] | None, str | None]:
    """Return (sbom, asset_id) for a container image digest, or (None, None)
    when the row is missing. Blob-missing returns (None, asset_id) so the
    caller can still scope-check before deciding 404 vs 403."""
    async def _query(session):
        result = await session.execute(
            select(Sbom).where(Sbom.commit_sha == image_digest).limit(1)
        )
        return result.scalars().first()

    row = run_db(_query)
    if row is None:
        return None, None
    sbom = download_from_minio(row.s3_key)
    return sbom, row.asset_id


def sbom_diff(
    *,
    repo_id: Optional[str] = None,
    from_run_id: Optional[str] = None,
    to_run_id: Optional[str] = None,
    image_digest_from: Optional[str] = None,
    image_digest_to: Optional[str] = None,
    info_context: dict,
) -> SbomDiffOrError:
    """Diff two SBOMs by repo+run or by container image digests.

    Either provide ``(repo_id, from_run_id, to_run_id)`` or
    ``(image_digest_from, image_digest_to)``. All not-found / out-of-scope
    paths return a uniform NOT_FOUND error so callers cannot distinguish
    "repo doesn't exist" from "you cannot see this repo".
    """
    asset_ids = info_context.get("asset_ids", [])
    not_found = SbomDiffError(message="One or both SBOMs not found.", code="NOT_FOUND")

    if repo_id is not None:
        if not from_run_id or not to_run_id:
            return SbomDiffError(
                message="from_run_id and to_run_id are required when repo_id is provided.",
                code="BAD_REQUEST",
            )
        parsed = _validate_repo_id(repo_id)
        if parsed is None or not _safe_run_id(from_run_id) or not _safe_run_id(to_run_id):
            return not_found
        if not _repo_in_scope_async(repo_id, asset_ids):
            return not_found
        owner, name = parsed
        from_sbom = download_json(f"dependencies_scanning/{owner}/{from_run_id}/{name}/sbom.cdx.json")
        to_sbom = download_json(f"dependencies_scanning/{owner}/{to_run_id}/{name}/sbom.cdx.json")
    elif image_digest_from and image_digest_to:
        if not _IMAGE_DIGEST_PATTERN.match(image_digest_from) or not _IMAGE_DIGEST_PATTERN.match(image_digest_to):
            return not_found
        from_sbom, from_asset = _fetch_container_sbom_by_digest(image_digest_from)
        to_sbom, to_asset = _fetch_container_sbom_by_digest(image_digest_to)
        scope = set(asset_ids)
        if (from_asset and from_asset not in scope) or (to_asset and to_asset not in scope):
            return not_found
    else:
        return SbomDiffError(
            message="Provide (repo_id + from_run_id + to_run_id) or (image_digest_from + image_digest_to).",
            code="BAD_REQUEST",
        )

    if from_sbom is None or to_sbom is None:
        return not_found

    diff = diff_sboms(from_sbom, to_sbom)
    return SbomDiffResult(
        added=[_component_to_diff(c) for c in diff.added],
        removed=[_component_to_diff(c) for c in diff.removed],
        version_changed=[
            SbomVersionChange(
                name=str(v.get("name") or ""),
                purl=str(v.get("purl") or ""),
                from_version=v.get("from_version"),
                to_version=v.get("to_version"),
            )
            for v in diff.version_changed
        ],
        unchanged_count=diff.unchanged_count,
    )
