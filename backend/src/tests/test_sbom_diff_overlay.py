"""compute_diff_overlay re-matches each changed component's from/to version
against the OSV mirror and overlays the advisory set-delta (resolved / introduced
/ dropped) plus current open findings, with an availability flag."""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from sqlalchemy import delete  # noqa: E402

import src.sbom.diff_overlay as overlay_mod  # noqa: E402
from src.db.helpers import run_db  # noqa: E402
from src.db.models import (  # noqa: E402
    Asset, Finding, OsvAdvisory, OsvVulnerableRange,
)
from src.sbom.diff import ComponentDiff, diff_sboms  # noqa: E402
from src.sbom.diff_overlay import compute_diff_overlay


def _now() -> datetime:
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


async def _seed_advisory(db_session, adv_id: str, severity: str, pkg: str,
                         introduced: str, fixed: str) -> None:
    db_session.add(OsvAdvisory(
        advisory_id=adv_id, ecosystem="npm", severity=severity,
        blob_key=f"osv/{adv_id}.json", modified_at=_now(), refreshed_at=_now(),
    ))
    await db_session.flush()
    db_session.add(OsvVulnerableRange(
        advisory_id=adv_id, package_name=pkg, ecosystem="npm",
        range_introduced=introduced, range_fixed=fixed, range_last_affected=None,
    ))
    await db_session.commit()


async def _cleanup_advisories(db_session, *adv_ids: str) -> None:
    for aid in adv_ids:
        await db_session.execute(delete(OsvVulnerableRange).where(OsvVulnerableRange.advisory_id == aid))
        await db_session.execute(delete(OsvAdvisory).where(OsvAdvisory.advisory_id == aid))
    await db_session.commit()


def _npm(name: str, version: str) -> dict:
    return {"name": name, "version": version, "purl": f"pkg:npm/{name}", "type": "library"}


@pytest.mark.asyncio
async def test_overlay_resolved_introduced_dropped_and_findings(db_session):
    # log4j <2.0.0 critical; left-pad <0.2.0 high; vulnpkg <2.0.0 medium.
    await _seed_advisory(db_session, "ADV-LOG4J", "critical", "log4j", "0", "2.0.0")
    await _seed_advisory(db_session, "ADV-LEFTPAD", "high", "left-pad", "0", "0.2.0")
    await _seed_advisory(db_session, "ADV-VULNPKG", "medium", "vulnpkg", "0", "2.0.0")

    asset = str(uuid.uuid4())
    db_session.add(Asset(
        id=asset, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/api",
    ))
    await db_session.flush()
    db_session.add(Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset,
        state="open", severity="high", package_name="left-pad", cve_id="CVE-X",
    ))
    await db_session.commit()

    diff = ComponentDiff(
        added=[_npm("left-pad", "0.1.0")],          # vulnerable now
        removed=[_npm("vulnpkg", "1.0.0")],          # dropped a vulnerable package
        version_changed=[{"name": "log4j", "purl": "pkg:npm/log4j",
                          "from_version": "1.0.0", "to_version": "2.5.0"}],  # 1.0.0 vuln -> 2.5.0 fixed
        unchanged_count=0,
    )

    try:
        ov = run_db(lambda s: compute_diff_overlay(s, diff, asset))

        assert ov.available is True

        # version bump that fixed the only advisory -> resolved, nothing left.
        resolved, introduced, still = ov.version_delta("log4j", "1.0.0", "2.5.0", "pkg:npm/log4j")
        assert resolved["critical"] == 1 and resolved["total"] == 1
        assert introduced["total"] == 0 and still["total"] == 0

        # added package is currently vulnerable (knownVulns) AND carries an open finding.
        assert ov.known_vulns("left-pad", "0.1.0", "pkg:npm/left-pad")["high"] == 1
        assert ov.findings_for("left-pad")["high"] == 1

        # removed package dropped a known-vulnerable version.
        assert ov.known_vulns("vulnpkg", "1.0.0", "pkg:npm/vulnpkg")["medium"] == 1

        # a clean version has no advisories.
        assert ov.known_vulns("log4j", "2.5.0", "pkg:npm/log4j")["total"] == 0
    finally:
        await _cleanup_advisories(db_session, "ADV-LOG4J", "ADV-LEFTPAD", "ADV-VULNPKG")
        await db_session.execute(delete(Finding).where(Finding.asset_id == asset))
        await db_session.execute(delete(Asset).where(Asset.id == asset))
        await db_session.commit()


@pytest.mark.asyncio
async def test_versioned_purl_bump_is_a_set_delta_not_double_counted(db_session):
    # The realistic path: production purls embed the version, so a bump must
    # still classify as version_changed (not add+remove) and a CVE affecting
    # BOTH versions must net to "still", never both "resolved" and "introduced".
    await _seed_advisory(db_session, "ADV-FIXED", "critical", "lib", "0", "2.0.0")   # fixed by the bump
    await _seed_advisory(db_session, "ADV-PERSIST", "high", "lib", "0", "9.0.0")     # affects both versions

    # Versioned purls — exactly what syft/cdxgen emit.
    from_sbom = {"components": [{"name": "lib", "version": "1.0.0", "purl": "pkg:npm/lib@1.0.0"}]}
    to_sbom = {"components": [{"name": "lib", "version": "2.0.0", "purl": "pkg:npm/lib@2.0.0"}]}
    diff = diff_sboms(from_sbom, to_sbom)

    try:
        # The bump is a version change, not an add + remove pair.
        assert diff.added == [] and diff.removed == []
        assert len(diff.version_changed) == 1

        ov = run_db(lambda s: compute_diff_overlay(s, diff, None))
        resolved, introduced, still = ov.version_delta("lib", "1.0.0", "2.0.0", "pkg:npm/lib")
        assert resolved["critical"] == 1 and resolved["total"] == 1   # the fixed CVE
        assert introduced["total"] == 0                               # nothing new
        assert still["high"] == 1 and still["total"] == 1             # the persistent CVE — not double-counted
    finally:
        await _cleanup_advisories(db_session, "ADV-FIXED", "ADV-PERSIST")


@pytest.mark.asyncio
async def test_overlay_unavailable_over_cap(db_session, monkeypatch):
    await _seed_advisory(db_session, "ADV-CAP", "critical", "log4j", "0", "2.0.0")
    monkeypatch.setattr(overlay_mod, "MAX_OVERLAY_COMPONENTS", 1)
    diff = ComponentDiff(
        added=[_npm("log4j", "1.0.0"), _npm("left-pad", "0.1.0")],  # 2 refs > cap of 1
        removed=[], version_changed=[], unchanged_count=0,
    )
    try:
        ov = run_db(lambda s: compute_diff_overlay(s, diff, None))
        assert ov.available is False
        # Over cap → no re-match performed, deltas read as zero (caller must not
        # treat this as "nothing vulnerable").
        assert ov.known_vulns("log4j", "1.0.0", "pkg:npm/log4j")["total"] == 0
    finally:
        await _cleanup_advisories(db_session, "ADV-CAP")


@pytest.mark.asyncio
async def test_overlay_unavailable_when_mirror_empty(db_session):
    # Ephemeral test DB: with no vulnerable ranges loaded the delta is unavailable,
    # never a misleading "all clear".
    await db_session.execute(delete(OsvVulnerableRange))
    await db_session.commit()
    diff = ComponentDiff(
        added=[_npm("log4j", "1.0.0")], removed=[], version_changed=[], unchanged_count=0,
    )
    ov = run_db(lambda s: compute_diff_overlay(s, diff, None))
    assert ov.available is False


def _pypi(name: str, version: str) -> dict:
    return {"name": name, "version": version, "purl": f"pkg:pypi/{name}", "type": "library"}


@pytest.mark.asyncio
async def test_overlay_unavailable_when_diff_ecosystem_not_mirrored(db_session):
    # A loaded mirror that only covers npm must NOT mark a PyPI-only diff as
    # available — otherwise an ecosystem the mirror hasn't ingested reads as
    # fully remediated. Coverage is scoped to the diff's own ecosystems.
    await _seed_advisory(db_session, "ADV-NPM-ONLY", "high", "left-pad", "0", "0.2.0")
    try:
        pypi_diff = ComponentDiff(
            added=[_pypi("requests", "2.0.0")], removed=[], version_changed=[], unchanged_count=0,
        )
        ov = run_db(lambda s: compute_diff_overlay(s, pypi_diff, None))
        assert ov.available is False, "PyPI diff should be unavailable when only npm is mirrored"

        # Sanity: an npm diff against the same mirror IS covered.
        npm_diff = ComponentDiff(
            added=[_npm("left-pad", "0.1.0")], removed=[], version_changed=[], unchanged_count=0,
        )
        ov_npm = run_db(lambda s: compute_diff_overlay(s, npm_diff, None))
        assert ov_npm.available is True
    finally:
        await _cleanup_advisories(db_session, "ADV-NPM-ONLY")
