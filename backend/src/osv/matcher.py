"""Match SBOM components against the OSV mirror to produce vulnerability hits.

Pure data: reads ``osv_vulnerable_ranges`` and compares versions with
``univers``. No subprocess and no network call, so the backend still never
executes a scanner tool (architecture rule 5).

A component is vulnerable to an advisory if its version falls inside any of that
advisory's flattened ranges for the same ecosystem + package. OSV interval
semantics: affected iff ``version >= introduced`` (``introduced`` "0" means from
the start) AND ``version < fixed`` (when a fix exists) AND
``version <= last_affected`` (when set).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import OsvVulnerableRange
from src.osv.ecosystems import osv_base_ecosystem, version_class_for

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ComponentRef:
    """One SBOM component to match.

    ``release_ecosystem`` is the component's release-specific OSV ecosystem
    (e.g. ``Debian:11``) when it can be mapped from the purl ``distro=``
    qualifier, else None. When set, matching is narrowed to advisories for that
    exact release so a (e.g.) Debian 11 package isn't flagged by a Debian 12-only
    advisory; when None, matching falls back to all releases of the base.
    """
    name: str
    version: str
    purl_type: str
    namespace: str | None = None
    release_ecosystem: str | None = None
    # The original package URL, carried for the premium Argus match. Excluded
    # from equality/hashing so two refs that differ only by purl still collapse
    # to one OSV-mirror match key.
    purl: str | None = field(default=None, compare=False)
    # Where the dep is declared (manifest path + line) plus a small code window,
    # carried from the SBOM component onto the finding for the drawer preview +
    # repo deep-link. Excluded from equality/hashing — carried data, not identity.
    manifest_path: str | None = field(default=None, compare=False)
    manifest_line: int | None = field(default=None, compare=False)
    manifest_snippet: str | None = field(default=None, compare=False)
    manifest_snippet_start: int | None = field(default=None, compare=False)
    # Dependency scope ("dev"/"prod") for a direct dep, else None. Carried data.
    scope: str | None = field(default=None, compare=False)
    # Introducing image layer (container components only): digest + 0-based
    # ordinal. Carried data, not identity.
    layer_digest: str | None = field(default=None, compare=False)
    layer_index: int | None = field(default=None, compare=False)


@dataclass(frozen=True)
class VulnMatch:
    """A confirmed (component, advisory) hit."""
    advisory_id: str
    package_name: str
    ecosystem: str
    version: str
    introduced: str | None
    fixed: str | None
    last_affected: str | None


def parse_purl(purl: str) -> tuple[str, str | None]:
    """Extract (type, namespace) from a package URL.

    ``pkg:deb/debian/openssl@1.1.1`` -> ("deb", "debian").
    ``pkg:npm/lodash@4.17.20``       -> ("npm", None).
    Returns ("", None) when the purl is absent or malformed.
    """
    if not purl or not purl.startswith("pkg:"):
        return "", None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    type_and_rest = body.split("/", 1)
    purl_type = type_and_rest[0].lower()
    namespace: str | None = None
    if len(type_and_rest) == 2:
        rest = type_and_rest[1]
        # namespace is everything before the last path segment (the name@version)
        segments = rest.split("/")
        if len(segments) >= 2:
            namespace = segments[0]
    return purl_type, namespace


def parse_purl_distro(purl: str) -> str | None:
    """Extract the ``distro`` qualifier from a purl
    (``pkg:deb/debian/openssl@1.1.1n?distro=debian-11`` -> ``debian-11``), or None.
    The distro/OS release is what pins a deb/apk/rpm package to a specific OSV
    release ecosystem."""
    if not purl or "?" not in purl:
        return None
    qualifiers = purl.split("?", 1)[1].split("#", 1)[0]
    for part in qualifiers.split("&"):
        key, _, value = part.partition("=")
        if key == "distro" and value:
            return value
    return None


def version_in_osv_range(
    version: str,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
    version_cls: type,
) -> bool:
    """Test whether ``version`` falls inside one flattened OSV interval.

    Unparseable versions fail closed for that single comparison (return False)
    rather than raising — a bad version string must never crash a whole scan.
    """
    try:
        v = version_cls(version)
    except Exception:
        return False

    if introduced and introduced != "0":
        try:
            if v < version_cls(introduced):
                return False
        except Exception:
            return False
    if fixed:
        try:
            if not (v < version_cls(fixed)):
                return False
        except Exception:
            return False
    if last_affected:
        try:
            if v > version_cls(last_affected):
                return False
        except Exception:
            return False
    return True


async def match_components(
    session: AsyncSession,
    components: list[ComponentRef],
) -> dict[ComponentRef, list[VulnMatch]]:
    """Match a batch of components against the OSV mirror.

    Groups components by OSV ecosystem and issues one query per ecosystem
    (``package_name IN (...)`` with an ecosystem prefix match so distro release
    suffixes like ``Debian:11`` are included). Returns only components that have
    at least one match.
    """
    # Group component names per OSV base ecosystem; skip unmapped/unsupported.
    names_by_base: dict[str, set[str]] = {}
    comps_by_key: dict[tuple[str, str], list[ComponentRef]] = {}
    for c in components:
        base = osv_base_ecosystem(c.purl_type, c.namespace)
        if not base or version_class_for(base) is None or not c.name or not c.version:
            continue
        names_by_base.setdefault(base, set()).add(c.name)
        comps_by_key.setdefault((base, c.name), []).append(c)

    results: dict[ComponentRef, list[VulnMatch]] = {}

    for base, names in names_by_base.items():
        version_cls = version_class_for(base)
        stmt = (
            select(OsvVulnerableRange)
            .where(OsvVulnerableRange.package_name.in_(names))
            .where(
                or_(
                    OsvVulnerableRange.ecosystem == base,
                    OsvVulnerableRange.ecosystem.like(f"{base}:%"),
                )
            )
        )
        rows = (await session.execute(stmt)).scalars().all()
        for row in rows:
            row_is_release_specific = ":" in row.ecosystem
            for comp in comps_by_key.get((base, row.package_name), []):
                # Release narrowing: a component pinned to a known release only
                # matches advisories for that release (or release-agnostic base
                # advisories). Components with no mapped release keep matching all
                # releases — never narrowed, so a real advisory is never dropped.
                if (
                    comp.release_ecosystem is not None
                    and row_is_release_specific
                    and row.ecosystem != comp.release_ecosystem
                ):
                    continue
                if version_in_osv_range(
                    comp.version,
                    row.range_introduced,
                    row.range_fixed,
                    row.range_last_affected,
                    version_cls,
                ):
                    results.setdefault(comp, []).append(
                        VulnMatch(
                            advisory_id=row.advisory_id,
                            package_name=row.package_name,
                            ecosystem=row.ecosystem,
                            version=comp.version,
                            introduced=row.range_introduced,
                            fixed=row.range_fixed,
                            last_affected=row.range_last_affected,
                        )
                    )

    # De-duplicate advisory hits per component (an advisory can flatten to
    # several intervals; one match is enough).
    for comp, matches in results.items():
        seen: set[str] = set()
        deduped: list[VulnMatch] = []
        for m in matches:
            if m.advisory_id in seen:
                continue
            seen.add(m.advisory_id)
            deduped.append(m)
        results[comp] = deduped

    return results
