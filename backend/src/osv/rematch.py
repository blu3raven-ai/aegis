"""Re-match indexed SBOMs against the OSV mirror, in the backend.

When the OSV catalog changes, re-evaluate existing SBOMs directly — no runner
round-trip — so newly disclosed advisories raise findings without a rescan.
This replaces the old dispatch of runner ``advisories_only`` jobs, which is now
redundant because the backend matches SBOMs itself.

Pure data: reads ``SbomComponent`` + OSV ranges and writes findings through the
existing lifecycle. A whole ``(tool, source_type, org)`` group is re-matched at
once so ``apply_lifecycle``'s diff (which is scoped to that group) closes truly
fixed findings without disturbing unrelated assets.
"""
from __future__ import annotations

import logging
from typing import Sequence

import sqlalchemy as sa

from src.db.helpers import run_db
from src.db.models import Asset, OsvVulnerableRange, SbomComponent
from src.osv.ecosystems import osv_base_ecosystem, osv_ecosystem_base
from src.osv.matcher import parse_purl

logger = logging.getLogger(__name__)

# asset.type -> (lifecycle tool, finding builder kind)
_TYPE_TO_TOOL = {
    "repo": ("dependencies_scanning", "dependencies"),
    "image": ("container_scanning", "container"),
}

# Above this many changed advisories, treat the reconcile as "everything" and
# re-match all SBOM-bearing groups rather than building a huge IN clause.
_FULL_RECONCILE_THRESHOLD = 5000


def _group_key(external_ref: str, asset_type: str) -> tuple[str, str, str, str] | None:
    """(tool, source_type, org, kind) for an asset, or None if unsupported."""
    tool_kind = _TYPE_TO_TOOL.get(asset_type)
    if not tool_kind or ":" not in external_ref:
        return None
    tool, kind = tool_kind
    source_type, rest = external_ref.split(":", 1)
    if "/" not in rest:
        return None
    org = rest.split("/", 1)[0]
    return tool, source_type, org, kind


async def _affected_asset_ids(session, changed_advisory_ids: list[str]) -> set[str]:
    """Asset ids whose SBOM components match a package in the changed advisories."""
    ranges = (await session.execute(
        sa.select(OsvVulnerableRange.ecosystem, OsvVulnerableRange.package_name)
        .where(OsvVulnerableRange.advisory_id.in_(changed_advisory_ids))
        .distinct()
    )).all()
    wanted = {(osv_ecosystem_base(eco), name) for eco, name in ranges}
    if not wanted:
        return set()

    names = {name for _, name in wanted}
    comps = (await session.execute(
        sa.select(
            SbomComponent.asset_id, SbomComponent.name,
            SbomComponent.ecosystem, SbomComponent.purl,
        ).where(SbomComponent.name.in_(names))
    )).all()

    affected: set[str] = set()
    for asset_id, name, eco, purl in comps:
        purl_type, namespace = parse_purl(purl)
        base = osv_base_ecosystem(purl_type or eco, namespace)
        if base and (base, name) in wanted:
            affected.add(asset_id)
    return affected


async def _sbom_assets(session) -> list[tuple[str, str, str]]:
    """(asset_id, external_ref, type) for every asset that has SBOM components."""
    rows = (await session.execute(
        sa.select(Asset.id, Asset.external_ref, Asset.type)
        .where(Asset.id.in_(sa.select(SbomComponent.asset_id).distinct()))
    )).all()
    return [(r[0], r[1], r[2]) for r in rows]


async def reconcile_sbom_matches(
    changed_advisory_ids: Sequence[str],
    *,
    refresh_run_id: int | None = None,
) -> int:
    """Re-match the SBOMs of affected groups against the current OSV mirror.

    Returns the number of findings produced across all re-matched groups. Safe
    to call with an empty list (returns 0).
    """
    if not changed_advisory_ids:
        return 0

    from src.osv.sca_findings import build_backend_match_findings

    changed = list(changed_advisory_ids)
    treat_full = len(changed) > _FULL_RECONCILE_THRESHOLD

    async def _build(session) -> dict[tuple[str, str, str], list[dict]]:
        assets = await _sbom_assets(session)
        groups: dict[tuple[str, str, str], list[tuple[str, str, str]]] = {}
        for asset_id, external_ref, asset_type in assets:
            gk = _group_key(external_ref, asset_type)
            if not gk:
                continue
            tool, source_type, org, kind = gk
            groups.setdefault((tool, source_type, org), []).append((asset_id, external_ref, kind))

        if treat_full:
            affected_groups = set(groups)
        else:
            affected = await _affected_asset_ids(session, changed)
            affected_groups = {
                key for key, members in groups.items()
                if any(asset_id in affected for asset_id, _, _ in members)
            }

        built: dict[tuple[str, str, str], list[dict]] = {}
        for key in affected_groups:
            out: list[dict] = []
            for asset_id, external_ref, kind in groups[key]:
                out.extend(await build_backend_match_findings(
                    session, asset_id=asset_id, external_ref=external_ref, kind=kind,
                ))
            built[key] = out
        return built

    built = run_db(_build)
    if not built:
        return 0

    from src.containers.lifecycle import container_scanning_hooks
    from src.dependencies.lifecycle import dependencies_hooks
    from src.shared.lifecycle import ScanContext, apply_lifecycle

    hooks_by_tool = {
        "dependencies_scanning": dependencies_hooks,
        "container_scanning": container_scanning_hooks,
    }
    run_tag = f"osv-reconcile:{refresh_run_id if refresh_run_id is not None else 'ondemand'}"

    total = 0
    for (tool, source_type, org), findings in built.items():
        if not findings:
            continue
        ctx = ScanContext(tool=tool, org=org, run_id=run_tag, source_type=source_type)
        apply_lifecycle(hooks_by_tool[tool], ctx, findings)
        total += len(findings)

    logger.info(
        "osv reconcile: re-matched %d group(s), produced %d finding(s) for %d changed advisories",
        len(built), total, len(changed),
    )
    return total
