"""In-process premium advisory matcher (the Argus premium-match shell).

Mirrors the free OSV matcher: resolve each component to an
``(ecosystem, package)`` coordinate, then test its version against each premium
advisory's vulnerable ranges using the ecosystem's real version scheme
(``univers``, via the shared ``src.osv`` helpers). Each hit becomes a
``MatchItem`` carrying the public advisory and the premium intel delta.

A component's coordinate comes from its explicit ``name``/``ecosystem`` when the
caller supplies them (exact), otherwise it is derived from the purl.

The shipped store is an intentionally-empty placeholder: no feed is wired, so the
matcher returns nothing in every deployment today and the free OSV match is
unaffected. A real feed/store is a future feature (see ``load_premium_store``).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable
from urllib.parse import unquote

from pydantic import BaseModel, Field

from src.osv.ecosystems import osv_base_ecosystem, version_class_for
from src.osv.matcher import version_in_osv_range

logger = logging.getLogger(__name__)


# --- Wire models --------------------------------------------------------------


class MatchComponent(BaseModel):
    """One SBOM component to match.

    ``purl`` + ``version`` is the minimum; the ecosystem and package name are
    derived from the purl. A caller that already holds the canonical coordinate
    should also send ``name`` (canonical package name) and ``ecosystem`` (OSV
    name, e.g. ``PyPI``) for exact matching — these take precedence over purl
    derivation.
    """

    purl: str | None = None
    version: str
    name: str | None = None
    ecosystem: str | None = None


class MatchPackage(BaseModel):
    name: str
    ecosystem: str | None = None


class MatchAdvisory(BaseModel):
    id: str
    cve_id: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    summary: str = ""
    description: str = ""
    html_url: str = ""
    references: list[dict[str, Any]] = Field(default_factory=list)
    published_at: str = ""
    vulnerable_version_range: str = ""
    first_patched_version: str | None = None


class PremiumIntel(BaseModel):
    """The premium intelligence delta the free OSV mirror cannot produce.

    Every field is signal that comes from a live intel feed rather than a static
    vulnerability database. It rides along each premium match so the consumer can
    prioritise far more precisely than severity alone. On a free-tier match the
    object is absent.
    """

    exploit_maturity: Literal["in_the_wild", "poc", "none"] | None = None
    affected_functions: list[str] = Field(default_factory=list)
    package_reputation: str | None = None
    epss_score: float | None = None
    epss_provenance: str | None = None
    kev_listed: bool = False
    aliases: list[str] = Field(default_factory=list)
    source: str | None = None
    last_synced: str | None = None


class MatchItem(BaseModel):
    """A single premium advisory hit against one component."""

    package: MatchPackage
    version: str
    manifest_path: str = ""
    advisory: MatchAdvisory
    # Additive: free-tier consumers ignore it, premium-aware consumers prioritise
    # on it.
    intel: PremiumIntel | None = None


class VulnerableRange(BaseModel):
    """One affected interval, in OSV's half-open semantics.

    A version is affected when ``version >= introduced`` and, when set,
    ``version < fixed`` and ``version <= last_affected``. ``introduced = "0"``
    with no upper bound means every version is affected.
    """

    introduced: str = "0"
    fixed: str | None = None
    last_affected: str | None = None


class PremiumAdvisoryRecord(BaseModel):
    """A premium advisory keyed to a single package coordinate.

    One entry in the premium feed: a package coordinate, its vulnerable version
    ranges, the public advisory payload, and the premium intel delta.
    """

    ecosystem: str
    package: str
    advisory: MatchAdvisory
    ranges: list[VulnerableRange] = Field(default_factory=list)
    intel: PremiumIntel = Field(default_factory=PremiumIntel)


# --- Store --------------------------------------------------------------------


@runtime_checkable
class PremiumAdvisoryStore(Protocol):
    """Read interface the matcher depends on, keyed by package coordinate."""

    def advisories_for(
        self, ecosystem: str, package: str
    ) -> list[PremiumAdvisoryRecord]:
        """Return premium advisories that may affect ``ecosystem``/``package``."""
        ...


class InMemoryPremiumStore:
    """Placeholder store backed by an in-memory index.

    Empty by default. Seed it from records in tests and local development;
    production would replace it with a feed-backed store.
    """

    def __init__(self, records: list[PremiumAdvisoryRecord] | None = None) -> None:
        self._by_key: dict[tuple[str, str], list[PremiumAdvisoryRecord]] = {}
        for record in records or []:
            self._by_key.setdefault(
                self._key(record.ecosystem, record.package), []
            ).append(record)

    @staticmethod
    def _key(ecosystem: str, package: str) -> tuple[str, str]:
        return ecosystem.strip().lower(), package.strip().lower()

    def advisories_for(
        self, ecosystem: str, package: str
    ) -> list[PremiumAdvisoryRecord]:
        return list(self._by_key.get(self._key(ecosystem, package), []))


def load_premium_store() -> PremiumAdvisoryStore:
    """Return the premium advisory store the matcher queries.

    Intentionally empty today — no feed is wired, so the free OSV match is
    unaffected. Populating this from a real premium feed is a future feature.
    """
    return InMemoryPremiumStore()


# --- Coordinate resolution ----------------------------------------------------


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
    store: PremiumAdvisoryStore | None = None,
) -> list[MatchItem]:
    """Return premium advisory hits for ``components``.

    Empty by default (the placeholder store holds nothing), so the free OSV match
    is unaffected until a premium feed is wired via ``load_premium_store``.
    ``store`` is injectable for tests and for callers that hold their own feed.
    """
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
                version_in_osv_range(
                    component.version,
                    r.introduced,
                    r.fixed,
                    r.last_affected,
                    version_cls,
                )
                for r in record.ranges
            ):
                hits.append(_to_match_item(component, record, ecosystem, name))
    if hits:
        logger.info("argus premium match: %d hit(s) on surface %s", len(hits), surface)
    return hits
