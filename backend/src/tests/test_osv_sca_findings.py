"""Tests for building backend-match findings from an asset's SBOM components.

Verifies the produced finding shape and, critically, that running the findings
through the existing lifecycle resolves to the SAME asset the components belong
to (no duplicate asset rows).
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.db.engine import DATABASE_URL
from src.db.models import Asset, Sbom, SbomComponent
from src.osv.store import OsvStore


def _adv(adv_id, ecosystem, name, fixed, *, cve=None, severity="HIGH"):
    return {
        "id": adv_id,
        "summary": f"{name} vuln",
        "details": f"{name} has a flaw",
        "aliases": [cve] if cve else [],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"severity": severity},
        "references": [{"type": "WEB", "url": f"https://example.test/{adv_id}"}],
        "published": "2026-06-01T00:00:00Z",
        "modified": "2026-06-10T00:00:00Z",
        "affected": [{
            "package": {"name": name, "ecosystem": ecosystem},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
        }],
    }


_BODIES = {
    "GHSA-lodash": _adv("GHSA-lodash", "npm", "lodash", "4.17.21", cve="CVE-2021-23337"),
    "PYSEC-req": _adv("PYSEC-req", "PyPI", "requests", "2.31.0", severity="MODERATE"),
}


async def _new_session():
    engine = create_async_engine(DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, factory


@pytest.mark.asyncio
async def test_build_and_roundtrip_to_existing_asset(monkeypatch):
    store = OsvStore()
    monkeypatch.setattr("src.osv.store._upload_blob", lambda *a, **k: None)
    # Lifecycle offloads "fat" detail fields to MinIO; the isolated-DB test
    # harness has no object store, so stub the blob write.
    monkeypatch.setattr("src.shared.finding_detail_blob.put_detail_blob", lambda *a, **k: None)
    # The builder reads advisory bodies from MinIO; serve them from memory.
    monkeypatch.setattr(
        "src.osv.sca_findings._download_blob",
        lambda key, bucket=None: __import__("json").dumps(
            _BODIES[key.split("/")[-1].removesuffix(".json")]
        ).encode(),
    )
    await store.upsert_advisories([_BODIES["GHSA-lodash"]], ecosystem="npm")
    await store.upsert_advisories([_BODIES["PYSEC-req"]], ecosystem="PyPI")

    asset_id = str(uuid.uuid4())
    engine, factory = await _new_session()
    try:
        async with factory() as s:
            s.add(Asset(
                id=asset_id, type="repo", source="source_connection",
                external_ref="github:acme/app", display_name="acme/app", asset_metadata={},
            ))
            s.add(Sbom(
                asset_id=asset_id, commit_sha="HEAD", s3_key="k", run_id="r1",
                html_url="https://ghe.acme-corp.internal/acme/app",
            ))
            for purl, name, ver, eco, mpath, mline, msnip, mstart in [
                ("pkg:npm/lodash@4.17.20", "lodash", "4.17.20", "npm",
                 "package.json", 12, '  "lodash": "^4.17.0"', 8),
                ("pkg:pypi/requests@2.30.0", "requests", "2.30.0", "pypi", None, None, None, None),
                ("pkg:npm/leftpad@1.0.0", "leftpad", "1.0.0", "npm", None, None, None, None),  # no advisory
            ]:
                s.add(SbomComponent(
                    asset_id=asset_id, purl=purl, name=name, version=ver, ecosystem=eco,
                    manifest_path=mpath, manifest_line=mline,
                    manifest_snippet=msnip, manifest_snippet_start=mstart,
                ))
            await s.commit()

        from src.osv.sca_findings import build_backend_match_findings
        async with factory() as s:
            raw = await build_backend_match_findings(
                s, asset_id=asset_id, external_ref="github:acme/app", kind="dependencies",
            )
    finally:
        from sqlalchemy import delete
        async with factory() as s:
            await s.execute(delete(SbomComponent).where(SbomComponent.asset_id == asset_id))
            await s.execute(delete(Sbom).where(Sbom.asset_id == asset_id))
            await s.execute(delete(Asset).where(Asset.id == asset_id))
            await s.commit()
        await engine.dispose()

    by_pkg = {f["dependency"]["package"]["name"]: f for f in raw}
    assert set(by_pkg) == {"lodash", "requests"}
    lod = by_pkg["lodash"]
    assert lod["security_advisory"]["ghsa_id"] == "GHSA-lodash"
    assert lod["security_advisory"]["cve_id"] == "CVE-2021-23337"
    assert lod["security_advisory"]["severity"] == "high"
    assert lod["security_vulnerability"]["first_patched_version"] == {"identifier": "4.17.21"}
    assert lod["current_version"] == "4.17.20"
    assert lod["repository"] == {"name": "app", "full_name": "acme/app"}
    assert lod["match_source"] == "scan"  # default when no explicit source given
    assert by_pkg["requests"]["security_advisory"]["severity"] == "medium"

    # Asset round-trip: the lifecycle hook must reproduce the asset's exact
    # external_ref from the built finding, so apply_lifecycle attaches to the
    # existing asset instead of creating a duplicate.
    from src.shared.lifecycle import ScanContext
    from src.dependencies.lifecycle import dependencies_hooks

    ctx = ScanContext(tool="dependencies_scanning", org="acme", run_id="osv-1", source_type="github")
    assert dependencies_hooks.canonical_external_ref(ctx, lod) == ("github:acme/app", "repo")
    # identity key is stable + advisory-specific, and includes the manifest path
    assert dependencies_hooks.compute_identity_key(lod) == "app::lodash::npm::GHSA-lodash::package.json"

    # Manifest declaration site flows from the SBOM component onto the finding
    # and surfaces as the generic code-window preview + git-blame location.
    assert lod["dependency"]["manifest_path"] == "package.json"
    assert lod["manifest_line"] == 12
    assert lod["manifest_snippet"] == '  "lodash": "^4.17.0"'
    assert lod["manifest_snippet_start"] == 8
    lod_detail = dependencies_hooks.extract_detail(lod)
    assert lod_detail["manifestPath"] == "package.json"
    assert lod_detail["startLine"] == 12
    assert lod_detail["code_window"] == '  "lodash": "^4.17.0"'
    assert lod_detail["code_window_start_line"] == 8
    assert dependencies_hooks.extract_file_location(lod) == ("package.json", 12)
    # requests has no manifest data -> git-blame location hook returns None
    assert dependencies_hooks.extract_file_location(by_pkg["requests"]) is None

    # Repo web URL (from the asset's Sbom row) flows onto every deps finding and
    # surfaces via extract_detail -> repoHtmlUrl for the view-in-repo deep-link.
    assert lod["repo_html_url"] == "https://ghe.acme-corp.internal/acme/app"
    assert lod_detail["repoHtmlUrl"] == "https://ghe.acme-corp.internal/acme/app"
    assert by_pkg["requests"]["repo_html_url"] == "https://ghe.acme-corp.internal/acme/app"


_MAL_BODY = {
    # A malicious-package report shaped like the OSV malicious-packages dataset:
    # names the package, carries no ranges/versions and no CVSS.
    "id": "MAL-2026-0001",
    "summary": "",
    "details": "npm package evil-pkg exfiltrates environment variables on install.",
    "aliases": [],
    "references": [{"type": "WEB", "url": "https://example.test/MAL-2026-0001"}],
    "published": "2026-06-01T00:00:00Z",
    "modified": "2026-06-01T00:00:00Z",
    "affected": [{"package": {"name": "evil-pkg", "ecosystem": "npm"}}],
}


@pytest.mark.asyncio
async def test_malicious_advisory_matches_and_builds_critical_finding(monkeypatch):
    """A MAL- advisory with no version range is ingested with an affects-all
    row, matches any installed version, and yields an open critical finding."""
    store = OsvStore()
    monkeypatch.setattr("src.osv.store._upload_blob", lambda *a, **k: None)
    monkeypatch.setattr("src.shared.finding_detail_blob.put_detail_blob", lambda *a, **k: None)
    monkeypatch.setattr(
        "src.osv.sca_findings._download_blob",
        lambda key, bucket=None: __import__("json").dumps(_MAL_BODY).encode(),
    )
    await store.upsert_advisories([_MAL_BODY], ecosystem="npm")

    asset_id = str(uuid.uuid4())
    engine, factory = await _new_session()
    try:
        async with factory() as s:
            s.add(Asset(
                id=asset_id, type="repo", source="source_connection",
                external_ref="github:acme/app", display_name="acme/app", asset_metadata={},
            ))
            s.add(Sbom(asset_id=asset_id, commit_sha="HEAD", s3_key="k", run_id="r1"))
            s.add(SbomComponent(
                asset_id=asset_id, purl="pkg:npm/evil-pkg@9.9.9",
                name="evil-pkg", version="9.9.9", ecosystem="npm", manifest_path="package.json",
            ))
            await s.commit()

        from src.osv.sca_findings import build_backend_match_findings
        async with factory() as s:
            raw = await build_backend_match_findings(
                s, asset_id=asset_id, external_ref="github:acme/app", kind="dependencies",
            )
    finally:
        from sqlalchemy import delete
        async with factory() as s:
            await s.execute(delete(SbomComponent).where(SbomComponent.asset_id == asset_id))
            await s.execute(delete(Sbom).where(Sbom.asset_id == asset_id))
            await s.execute(delete(Asset).where(Asset.id == asset_id))
            await s.commit()
        await engine.dispose()

    assert len(raw) == 1
    finding = raw[0]
    assert finding["malicious"] is True
    assert finding["security_advisory"]["severity"] == "critical"
    assert finding["security_advisory"]["summary"] == "Malicious package: evil-pkg"

    from src.dependencies.lifecycle import dependencies_hooks
    assert dependencies_hooks.initial_state(finding) == "open"


@pytest.mark.asyncio
async def test_container_findings_roundtrip_to_image_asset(monkeypatch):
    body = _adv("GHSA-zlib", "Alpine", "zlib", "1.2.13-r1", cve="CVE-2022-37434")
    store = OsvStore()
    monkeypatch.setattr("src.osv.store._upload_blob", lambda *a, **k: None)
    monkeypatch.setattr(
        "src.osv.sca_findings._download_blob",
        lambda key, bucket=None: __import__("json").dumps(body).encode(),
    )
    await store.upsert_advisories([body], ecosystem="Alpine")

    asset_id = str(uuid.uuid4())
    engine, factory = await _new_session()
    try:
        async with factory() as s:
            s.add(Asset(
                id=asset_id, type="image", source="source_connection",
                external_ref="ghcr:acme/app:1.2.3", display_name="acme/app:1.2.3", asset_metadata={},
            ))
            s.add(SbomComponent(
                asset_id=asset_id, purl="pkg:apk/alpine/zlib@1.2.13-r0",
                name="zlib", version="1.2.13-r0", ecosystem="apk",
            ))
            await s.commit()

        from src.osv.sca_findings import build_backend_match_findings
        async with factory() as s:
            raw = await build_backend_match_findings(
                s, asset_id=asset_id, external_ref="ghcr:acme/app:1.2.3", kind="container",
            )
    finally:
        await engine.dispose()

    assert len(raw) == 1
    f = raw[0]
    assert f["imageName"] == "acme/app" and f["imageTag"] == "1.2.3"
    assert f["dependency"]["package"]["name"] == "zlib"
    assert f["security_advisory"]["ghsa_id"] == "GHSA-zlib"

    from src.shared.lifecycle import ScanContext
    from src.containers.lifecycle import container_scanning_hooks

    ctx = ScanContext(tool="container_scanning", org="acme", run_id="osv-1", source_type="ghcr")
    assert container_scanning_hooks.canonical_external_ref(ctx, f) == ("ghcr:acme/app:1.2.3", "image")


def _raw_dep_finding(match_source: str) -> dict:
    """Minimal nested raw finding in the shape the lifecycle hooks parse."""
    return {
        "repository": {"name": "app", "full_name": "acme/app"},
        "dependency": {"package": {"name": "lodash", "ecosystem": "npm"}, "manifest_path": ""},
        "security_advisory": {
            "ghsa_id": "GHSA-x", "cve_id": None, "severity": "high", "cvss": {},
            "summary": "", "description": "", "html_url": "", "references": [], "published_at": "",
        },
        "security_vulnerability": {"vulnerable_version_range": "", "first_patched_version": None},
        "current_version": "1.0.0",
        "match_source": match_source,
    }


def test_match_source_flows_into_lean_queryable_detail():
    """matchSource must reach the JSONB column (lean), not the MinIO blob, so an
    audit query can filter findings by how they were first surfaced."""
    from src.dependencies.lifecycle import dependencies_hooks
    from src.containers.lifecycle import container_scanning_hooks
    from src.shared.finding_detail_blob import split_detail

    raw = _raw_dep_finding("overlay")
    detail = dependencies_hooks.extract_detail(raw)
    assert detail["matchSource"] == "overlay"
    lean, fat = split_detail("dependencies_scanning", detail)
    assert lean["matchSource"] == "overlay"
    assert "matchSource" not in fat

    craw = dict(raw, imageName="acme/app", imageTag="1.0.0")
    cdetail = container_scanning_hooks.extract_detail(craw)
    assert cdetail["matchSource"] == "overlay"
    clean, _ = split_detail("container_scanning", cdetail)
    assert clean["matchSource"] == "overlay"


def test_malicious_flag_keeps_finding_open_with_no_fix():
    """A malicious package has no fix but must never be deferred — deferral would
    hide a compromised dependency."""
    from src.dependencies.lifecycle import dependencies_hooks
    from src.containers.lifecycle import container_scanning_hooks

    benign = _raw_dep_finding("scan")
    assert dependencies_hooks.initial_state(benign) == "deferred"  # no fix → deferred

    malicious = dict(benign, malicious=True)
    assert dependencies_hooks.initial_state(malicious) == "open"
    assert dependencies_hooks.extract_detail(malicious)["malicious"] is True

    cmal = dict(malicious, imageName="acme/app", imageTag="1.0.0")
    assert container_scanning_hooks.initial_state(cmal) == "open"
    assert container_scanning_hooks.extract_detail(cmal)["malicious"] is True


def test_build_raw_finding_marks_malicious_advisory_critical():
    """MAL- advisories are forced critical, flagged malicious, and given a
    package-named summary when the advisory body carries none."""
    from src.osv.matcher import ComponentRef, VulnMatch
    from src.osv.sca_findings import _build_raw_finding

    comp = ComponentRef(name="evil-pkg", version="1.2.3", purl_type="npm",
                        manifest_path="package.json")
    match = VulnMatch(
        advisory_id="MAL-2024-9999", package_name="evil-pkg", ecosystem="npm",
        version="1.2.3", introduced="0", fixed=None, last_affected=None,
    )
    raw = _build_raw_finding(
        kind="dependencies", repo_name="app", repo_full_name="acme/app",
        image_name=None, image_tag=None, comp=comp, match=match,
        adv_body={"id": "MAL-2024-9999", "summary": ""}, match_source="scan",
    )
    assert raw["malicious"] is True
    assert raw["security_advisory"]["severity"] == "critical"
    assert raw["security_advisory"]["summary"] == "Malicious package: evil-pkg"


def test_preserve_match_source_is_first_write_wins():
    """A later run (e.g. a scan re-touching an overlay-surfaced finding) must not
    rewrite the original provenance."""
    from src.shared.lifecycle import _preserve_match_source

    prev = {"matchSource": "overlay", "ecosystem": "npm"}
    incoming = {"matchSource": "scan", "ecosystem": "npm"}
    assert _preserve_match_source(prev, incoming)["matchSource"] == "overlay"
    # legacy row with no stored provenance backfills from the incoming detail
    assert _preserve_match_source({"ecosystem": "npm"}, incoming)["matchSource"] == "scan"
    # no prior detail at all — incoming wins
    assert _preserve_match_source(None, incoming)["matchSource"] == "scan"
