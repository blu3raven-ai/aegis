"""Match SBOM components against the premium advisory store.

The engine mirrors the free OSV matcher: resolve each component to an
``(ecosystem, package)`` coordinate, then test its version against each
advisory's vulnerable ranges using the ecosystem's real version scheme
(``univers``). Each hit becomes a ``MatchItem`` carrying the public advisory and
the premium intel delta.

A component's coordinate comes from its explicit ``name``/``ecosystem`` when the
integrator supplies them (exact), otherwise it is derived from the purl.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import unquote

from argus.matching.ecosystems import (
    osv_base_ecosystem,
    version_class_for,
    version_in_range,
)
from argus.matching.entitlement import EntitlementChecker, default_entitlement_checker
from argus.matching.models import PremiumAdvisoryRecord
from argus.matching.store import PremiumAdvisoryStore, load_premium_store
from argus.models import MatchComponent, MatchItem, MatchPackage

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PurlCoordinate:
    """The parts of a purl the matcher needs."""

    purl_type: str | None
    namespace: str | None
    name: str | None


def parse_purl(purl: str | None) -> PurlCoordinate:
    """Parse ``pkg:<type>/<namespace>/<name>@<version>?<quals>#<sub>``.

    Returns the type, namespace (everything between type and the final segment,
    decoded) and the final name segment. All-``None`` when ``purl`` is absent or
    not a package URL.
    """
    if not purl or not purl.startswith("pkg:"):
        return PurlCoordinate(None, None, None)
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    purl_type, _, rest = body.partition("/")
    if not rest:
        return PurlCoordinate(None, None, None)
    rest = rest.split("@", 1)[0]  # drop version
    segments = [unquote(s) for s in rest.split("/") if s]
    if not segments:
        return PurlCoordinate(purl_type.lower() or None, None, None)
    name = segments[-1]
    namespace = "/".join(segments[:-1]) or None
    return PurlCoordinate(purl_type.lower() or None, namespace, name)


def _canonical_name(coord: PurlCoordinate) -> str | None:
    """Canonical package name for the ecosystem, per OSV naming conventions.

    npm scopes and Go module paths keep the namespace with ``/``; Maven joins
    ``group:artifact``; other ecosystems use the bare name (distro namespaces
    only disambiguate the ecosystem, not the package name).
    """
    if not coord.name:
        return None
    if not coord.namespace:
        return coord.name
    if coord.purl_type in ("npm", "golang", "go"):
        return f"{coord.namespace}/{coord.name}"
    if coord.purl_type == "maven":
        return f"{coord.namespace}:{coord.name}"
    return coord.name


def _coordinate(component: MatchComponent) -> tuple[str | None, str | None]:
    """Resolve ``(osv_ecosystem, package_name)`` — explicit fields win over purl."""
    coord = parse_purl(component.purl)
    ecosystem = component.ecosystem or osv_base_ecosystem(
        coord.purl_type or "", coord.namespace
    )
    name = component.name or _canonical_name(coord)
    return ecosystem, name


def _to_match_item(
    component: MatchComponent,
    record: PremiumAdvisoryRecord,
    ecosystem: str | None,
    name: str | None,
) -> MatchItem:
    return MatchItem(
        package=MatchPackage(
            name=record.package or name or "",
            ecosystem=record.ecosystem or ecosystem,
        ),
        version=component.version,
        advisory=record.advisory,
        intel=record.intel,
    )


def match_components(
    surface: str,
    components: list[MatchComponent],
    *,
    org_id: str | None = None,
    store: PremiumAdvisoryStore | None = None,
    entitlement: EntitlementChecker | None = None,
) -> list[MatchItem]:
    """Return premium advisory hits for ``components``.

    Empty by default (the placeholder store holds nothing), so the free OSV match
    is unaffected until the premium feed is wired via ``load_premium_store``.

    ``org_id`` is the verified caller tenant. When present, its premium
    entitlement is checked first; an unentitled org gets an empty premium
    response (it falls back to the free match). ``store`` / ``entitlement`` are
    injectable for tests and for callers that hold their own feed.
    """
    if org_id is not None:
        checker = entitlement or default_entitlement_checker()
        if not checker.is_entitled(org_id, surface):
            return []
    store = store or load_premium_store()
    hits: list[MatchItem] = []
    for component in components:
        ecosystem, name = _coordinate(component)
        if not ecosystem or not name or not component.version:
            continue
        version_cls = version_class_for(ecosystem)
        if version_cls is None:
            continue
        for record in store.advisories_for(ecosystem, name):
            if any(
                version_in_range(component.version, r, version_cls)
                for r in record.ranges
            ):
                hits.append(_to_match_item(component, record, ecosystem, name))
    if hits:
        logger.info("argus premium match: %d hit(s) on surface %s", len(hits), surface)
    return hits
