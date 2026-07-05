"""Vulnerability overlay for SBOM diffs.

Two separately-labelled signals are layered onto a composition diff so an
analyst can tell whether a change introduced or remediated a vulnerable package:

- **Current findings** (Signal A): open findings on the to-side asset, by package
  name — "what is still open now". Version-agnostic, so it only reflects the
  asset's latest scan and is structurally empty for removed packages.
- **OSV re-match delta** (Signal B): each changed component's from/to version is
  re-matched against today's OSV mirror and the advisory sets are diffed
  (resolved / introduced / dropped). This is the only honest way to show
  remediation, but it is a *re-evaluation* against the current mirror, not a
  replay of the findings that existed at the old snapshot — so it is surfaced to
  the client as "advisories", never "findings", and flagged unavailable when the
  mirror is empty or the diff is too large to re-match within the query budget.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Finding, OsvAdvisory, OsvVulnerableRange
from src.osv.matcher import ComponentRef, match_components, parse_purl, parse_purl_distro
from src.osv.ecosystems import osv_base_ecosystem, osv_release_ecosystem
from src.sbom.diff import ComponentDiff

# Re-matching is per-component OSV work and the GraphQL query budget is small;
# container images carry thousands of OS packages, so cap how many distinct
# (name, version) refs we re-match and report the delta unavailable past it.
MAX_OVERLAY_COMPONENTS = 800

_TIERS = ("critical", "high", "medium", "low")


def _empty_bucket() -> dict[str, int]:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}


def _ref(name: str | None, version: str | None, purl: str | None) -> ComponentRef | None:
    """The OSV match ref for a component at one version. The purl carries the
    ecosystem discriminator (type + namespace) so two packages that share a name
    and version across ecosystems never collide."""
    if not name or not version:
        return None
    purl_type, namespace = parse_purl(purl or "")
    return ComponentRef(
        name=name, version=version, purl_type=purl_type, namespace=namespace,
        release_ecosystem=osv_release_ecosystem(parse_purl_distro(purl or "")),
    )


@dataclass
class DiffOverlay:
    """Computed overlay maps for one diff. ``available`` is the OSV-delta
    (Signal B) availability — false means the mirror is empty or the diff
    exceeded the re-match cap, so callers must not read the delta as zeros."""
    available: bool
    current_findings: dict[str, dict[str, int]]
    _ids_by_ref: dict[ComponentRef, set[str]]
    _sev_by_id: dict[str, str | None]

    def _bucket_ids(self, ids: set[str]) -> dict[str, int]:
        b = _empty_bucket()
        for aid in ids:
            tier = (self._sev_by_id.get(aid) or "").lower()
            if tier in _TIERS:
                b[tier] += 1
            b["total"] += 1
        return b

    def _ids(self, name: str | None, version: str | None, purl: str | None) -> set[str]:
        ref = _ref(name, version, purl)
        return self._ids_by_ref.get(ref, set()) if ref else set()

    def findings_for(self, name: str | None) -> dict[str, int]:
        if not name:
            return _empty_bucket()
        return self.current_findings.get(name, _empty_bucket())

    def known_vulns(self, name: str | None, version: str | None, purl: str | None) -> dict[str, int]:
        """Advisories affecting one component at a specific version."""
        return self._bucket_ids(self._ids(name, version, purl))

    def version_delta(
        self, name: str | None, from_version: str | None, to_version: str | None, purl: str | None
    ) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
        """(resolved, introduced, still_vulnerable) advisory buckets for a bump:
        resolved = on the old version but not the new, introduced = the reverse,
        still = on both."""
        f = self._ids(name, from_version, purl)
        t = self._ids(name, to_version, purl)
        return self._bucket_ids(f - t), self._bucket_ids(t - f), self._bucket_ids(f & t)


def _build_refs(diff: ComponentDiff) -> list[ComponentRef]:
    """Distinct refs to re-match: added/removed at their own version,
    version_changed at both ends."""
    refs: set[ComponentRef] = set()

    def add(name: str | None, version: str | None, purl: str | None) -> None:
        ref = _ref(name, version, purl)
        if ref is not None:
            refs.add(ref)

    for c in diff.added:
        add(c.get("name"), c.get("version"), c.get("purl"))
    for c in diff.removed:
        add(c.get("name"), c.get("version"), c.get("purl"))
    for v in diff.version_changed:
        add(v.get("name"), v.get("from_version"), v.get("purl"))
        add(v.get("name"), v.get("to_version"), v.get("purl"))
    return list(refs)


async def compute_diff_overlay(
    session: AsyncSession, diff: ComponentDiff, to_asset_id: str | None
) -> DiffOverlay:
    """Build the current-findings (Signal A) and OSV-delta (Signal B) maps for a
    diff. Signal A is scoped to ``to_asset_id`` (already resolved within the
    caller's grant set); Signal B reads public OSV mirror data and is asset
    independent."""
    # Signal A — current open findings on the to-side asset, by package name.
    current_findings: dict[str, dict[str, int]] = {}
    if to_asset_id:
        names = {c.get("name") for c in diff.added}
        names |= {v.get("name") for v in diff.version_changed}
        names.discard(None)
        if names:
            rows = (
                await session.execute(
                    select(Finding.package_name, Finding.severity, func.count())
                    .where(
                        Finding.asset_id == to_asset_id,
                        Finding.state == "open",
                        Finding.archived.is_(False),
                        Finding.package_name.in_(names),
                    )
                    .group_by(Finding.package_name, Finding.severity)
                )
            ).all()
            for pkg, sev, cnt in rows:
                bucket = current_findings.setdefault(pkg, _empty_bucket())
                tier = (sev or "").lower()
                if tier in _TIERS:
                    bucket[tier] += cnt
                bucket["total"] += cnt

    # Signal B — OSV re-match delta. Unavailable if the mirror doesn't cover this
    # diff (else a missing/partial mirror reads as a misleading "nothing
    # vulnerable") or the diff is too large to re-match within the query budget.
    refs = _build_refs(diff)
    # Scope the coverage probe to the diff's own ecosystems, mirroring how
    # match_components groups: a globally-loaded mirror that holds no ranges for
    # any ecosystem in this diff must still report unavailable, otherwise an
    # ecosystem the mirror hasn't ingested yet reads as fully remediated.
    diff_ecosystems = {
        base
        for ref in refs
        if (base := osv_base_ecosystem(ref.purl_type, ref.namespace)) is not None
    }
    if diff_ecosystems:
        # Require the mirror to cover EVERY ecosystem in the diff. A partial
        # mirror (e.g. npm ingested but not PyPI) would render the un-ingested
        # ecosystem's components as "0 introduced / 0 resolved" — a false
        # all-clear — so if any diff ecosystem is missing, the signal is
        # unavailable rather than misleadingly partial.
        present = (
            await session.execute(
                select(OsvVulnerableRange.ecosystem)
                .where(
                    or_(
                        OsvVulnerableRange.ecosystem.in_(diff_ecosystems),
                        *(OsvVulnerableRange.ecosystem.like(f"{base}:%") for base in diff_ecosystems),
                    )
                )
                .distinct()
            )
        ).scalars().all()
        # Release-specific rows (e.g. "debian:11") map back to their base.
        present_bases = {e.split(":", 1)[0] for e in present}
        mirror_loaded = diff_ecosystems.issubset(present_bases)
    else:
        # No re-matchable refs (empty or fully-unmapped diff) — no ecosystem to
        # scope to, so fall back to a global mirror-presence check.
        mirror_loaded = (
            await session.execute(select(OsvVulnerableRange.id).limit(1))
        ).first() is not None
    available = mirror_loaded and len(refs) <= MAX_OVERLAY_COMPONENTS

    ids_by_ref: dict[ComponentRef, set[str]] = {}
    sev_by_id: dict[str, str | None] = {}
    if available and refs:
        matched = await match_components(session, refs)
        all_ids: set[str] = set()
        for ref, matches in matched.items():
            ids = ids_by_ref.setdefault(ref, set())
            for m in matches:
                ids.add(m.advisory_id)
                all_ids.add(m.advisory_id)
        if all_ids:
            sev_rows = (
                await session.execute(
                    select(OsvAdvisory.advisory_id, OsvAdvisory.severity).where(
                        OsvAdvisory.advisory_id.in_(all_ids)
                    )
                )
            ).all()
            sev_by_id = {aid: sev for aid, sev in sev_rows}

    return DiffOverlay(
        available=available,
        current_findings=current_findings,
        _ids_by_ref=ids_by_ref,
        _sev_by_id=sev_by_id,
    )
