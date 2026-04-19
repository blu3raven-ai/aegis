"""GraphQL resolvers for SBOM component search and filter options."""
from __future__ import annotations

import logging
import re
from typing import Optional

import strawberry
from sqlalchemy import func, select, or_, and_

from src.db.helpers import run_db
from src.db.models import SbomComponent, Sbom

from src.graphql.limits import clamp_per_page

logger = logging.getLogger(__name__)

MAX_BULK_ITEMS = 500


def _escape_like(s: str) -> str:
    """Escape LIKE metacharacters so user input is treated as literal text."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


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
    """Search SBOM components across all user orgs."""
    per_page = clamp_per_page(per_page)
    search = (search or "")[:200] or None
    orgs = info_context.get("orgs", [])
    if not orgs:
        return SbomComponentsConnection(items=[], total=0, page=page, per_page=per_page, total_pages=0)

    use_or = filter_logic == "or"

    async def _query(session):
        base = select(SbomComponent).where(SbomComponent.org.in_([o.lower() for o in orgs]))

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
            group_conditions.append(SbomComponent.repo.in_(repos[:200]))

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
        ).scalars().all()

        # Apply version filtering in Python (semver comparison isn't reliable in SQL)
        if version_op and version_value:
            target = _parse_version_tuple(version_value)
            target_end = _parse_version_tuple(version_value_end) if version_value_end else None

            filtered = []
            for r in rows:
                v = _parse_version_tuple(r.version)
                if version_op == "eq" and v == target:
                    filtered.append(r)
                elif version_op == "gte" and v >= target:
                    filtered.append(r)
                elif version_op == "lte" and v <= target:
                    filtered.append(r)
                elif version_op == "range" and target_end and target <= v <= target_end:
                    filtered.append(r)

            # For version filtering we need to re-count by fetching all matching rows
            # and filtering. For simplicity, we do full scan with version filter.
            all_rows = (
                await session.execute(
                    base.order_by(SbomComponent.name, SbomComponent.version)
                )
            ).scalars().all()

            all_filtered = []
            for r in all_rows:
                v = _parse_version_tuple(r.version)
                if version_op == "eq" and v == target:
                    all_filtered.append(r)
                elif version_op == "gte" and v >= target:
                    all_filtered.append(r)
                elif version_op == "lte" and v <= target:
                    all_filtered.append(r)
                elif version_op == "range" and target_end and target <= v <= target_end:
                    all_filtered.append(r)

            total = len(all_filtered)
            rows = all_filtered[offset:offset + per_page]

        items = [
            SbomComponentNode(
                name=r.name,
                version=r.version,
                ecosystem=r.ecosystem,
                purl=r.purl,
                repo=r.repo,
                org=r.org,
                source_tool=r.source_tool,
                scanned_at=r.scanned_at.isoformat() if r.scanned_at else "",
            )
            for r in rows
        ]

        total_pages = (total + per_page - 1) // per_page if per_page > 0 else 0
        return SbomComponentsConnection(
            items=items, total=total, page=page, per_page=per_page, total_pages=total_pages
        )

    return run_db(_query)


def sbom_filter_options(*, info_context: dict) -> SbomFilterOptions:
    """Return available filter values for SBOM search."""
    orgs = info_context.get("orgs", [])
    if not orgs:
        return SbomFilterOptions(ecosystems=[], repositories=[], sources=[])

    async def _query(session):
        org_filter = SbomComponent.org.in_([o.lower() for o in orgs])

        eco_q = (
            select(SbomComponent.ecosystem)
            .where(org_filter, SbomComponent.ecosystem != "")
            .distinct()
            .order_by(SbomComponent.ecosystem)
        )
        ecosystems = [r[0] for r in (await session.execute(eco_q)).all()]

        repo_q = (
            select(SbomComponent.repo)
            .where(org_filter)
            .distinct()
            .order_by(SbomComponent.repo)
        )
        repositories = [r[0] for r in (await session.execute(repo_q)).all()]

        sources = ["dependencies", "containers"]

        return SbomFilterOptions(ecosystems=ecosystems, repositories=repositories, sources=sources)

    return run_db(_query)


def sbom_cross_references(
    *, purl: str, info_context: dict
) -> list[SbomCrossReference]:
    """Find all repos/images that contain a specific package (by PURL)."""
    orgs = info_context.get("orgs", [])
    if not orgs:
        return []

    async def _query(session):
        q = (
            select(SbomComponent)
            .where(
                SbomComponent.org.in_([o.lower() for o in orgs]),
                SbomComponent.purl == purl,
            )
            .order_by(SbomComponent.repo)
        )
        rows = (await session.execute(q)).scalars().all()
        return [
            SbomCrossReference(
                repo=r.repo,
                org=r.org,
                version=r.version,
                source_tool=r.source_tool,
                scanned_at=r.scanned_at.isoformat() if r.scanned_at else "",
            )
            for r in rows
        ]

    return run_db(_query)


def sbom_bulk_lookup(
    *, queries: list[str], info_context: dict
) -> list[SbomBulkMatch]:
    """Check which packages from a list exist in the estate."""
    orgs = info_context.get("orgs", [])
    if not orgs or not queries:
        return []

    clean = [q.strip() for q in queries[:MAX_BULK_ITEMS] if q.strip()]
    if not clean:
        return []

    async def _query(session):
        org_filter = SbomComponent.org.in_([o.lower() for o in orgs])
        results: list[SbomBulkMatch] = []

        for q in clean:
            conditions = [org_filter]

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
                    select(SbomComponent).where(and_(*conditions)).limit(100)
                )
            ).scalars().all()

            if rows:
                repos = sorted(set(r.repo for r in rows))
                first = rows[0]
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
