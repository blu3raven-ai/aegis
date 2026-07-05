"""Tests for the additive in-process premium SBOM match.

Three layers:
- ``match_components`` unit tests — empty placeholder store yields nothing; an
  injected seeded store yields the matched ``MatchItem``.
- ``_finding_from_match`` / ``match_via_argus`` tests — proving the
  ``MatchItem`` -> raw-finding-dict adaptation is byte-identical to the free OSV
  shape (this is the silent-drop guard).
- ``build_backend_match_findings`` integration tests — premium hits are appended
  additively, deduped against the free OSV set, and gated on the connection's
  ``enabled`` flag.
"""
from __future__ import annotations

import types
import uuid

import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.db.engine import DATABASE_URL
from src.db.models import Asset, SbomComponent
from src.osv.argus_match import _finding_from_match, match_via_argus
from src.osv.matcher import ComponentRef
from src.osv.premium_match import (
    InMemoryPremiumStore,
    MatchAdvisory,
    MatchComponent,
    MatchItem,
    MatchPackage,
    PremiumAdvisoryRecord,
    VulnerableRange,
    match_components,
)
from src.osv.store import OsvStore


def _record(name="lodash", fixed="4.17.21", advisory_id="ARGUS-1") -> PremiumAdvisoryRecord:
    """A premium advisory record whose range admits lodash 4.17.20."""
    return PremiumAdvisoryRecord(
        ecosystem="npm",
        package=name,
        advisory=MatchAdvisory(
            id=advisory_id,
            cve_id="CVE-2099-0001",
            severity="high",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            summary="premium-only flaw",
            description="only in the premium DB",
            html_url="https://example.test/adv/ARGUS-1",
            references=[{"url": "https://example.test/ref"}],
            published_at="2026-06-01T00:00:00Z",
            vulnerable_version_range=">= 0, < 4.17.21",
            first_patched_version="4.17.21",
        ),
        ranges=[VulnerableRange(introduced="0", fixed=fixed)],
    )


_COMPONENTS = [
    ComponentRef(
        name="lodash", version="4.17.20", purl_type="npm",
        purl="pkg:npm/lodash@4.17.20",
    )
]


# --- match_components: empty store vs seeded store ----------------------------


def test_match_components_empty_store_returns_empty():
    comps = [MatchComponent(purl="pkg:npm/lodash@4.17.20", version="4.17.20")]
    # No store injected -> the default placeholder store, which is empty.
    assert match_components("dependencies", comps) == []


def test_match_components_seeded_store_hits():
    store = InMemoryPremiumStore([_record()])
    comps = [MatchComponent(purl="pkg:npm/lodash@4.17.20", version="4.17.20")]

    out = match_components("dependencies", comps, store=store)

    assert len(out) == 1
    assert isinstance(out[0], MatchItem)
    assert out[0].package == MatchPackage(name="lodash", ecosystem="npm")
    assert out[0].version == "4.17.20"
    assert out[0].advisory.id == "ARGUS-1"


def test_match_components_seeded_store_version_out_of_range_misses():
    # Fixed at 4.17.20 -> the installed 4.17.20 is NOT < fixed, so no hit.
    store = InMemoryPremiumStore([_record(fixed="4.17.20")])
    comps = [MatchComponent(purl="pkg:npm/lodash@4.17.20", version="4.17.20")]

    assert match_components("dependencies", comps, store=store) == []


# --- MatchItem -> raw-finding-dict adaptation (silent-drop guard) -------------


def test_finding_from_match_maps_all_fields():
    item = MatchItem(
        package=MatchPackage(name="lodash", ecosystem="npm"),
        version="4.17.20",
        manifest_path="package.json",
        advisory=MatchAdvisory(
            id="ARGUS-1",
            cve_id="CVE-2099-0001",
            severity="high",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            summary="premium-only flaw",
            description="only in the premium DB",
            html_url="https://example.test/adv/ARGUS-1",
            references=[{"url": "https://example.test/ref"}],
            published_at="2026-06-01T00:00:00Z",
            vulnerable_version_range=">= 0, < 4.17.21",
            first_patched_version="4.17.21",
        ),
    )

    assert _finding_from_match(item) == {
        "repository": {"name": "", "full_name": ""},
        "dependency": {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "manifest_path": "package.json",
        },
        "security_advisory": {
            "ghsa_id": "ARGUS-1",
            "cve_id": "CVE-2099-0001",
            "severity": "high",
            "cvss": {
                "score": 7.5,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
            "summary": "premium-only flaw",
            "description": "only in the premium DB",
            "html_url": "https://example.test/adv/ARGUS-1",
            "references": [{"url": "https://example.test/ref"}],
            "published_at": "2026-06-01T00:00:00Z",
        },
        "security_vulnerability": {
            "vulnerable_version_range": ">= 0, < 4.17.21",
            "first_patched_version": {"identifier": "4.17.21"},
        },
        "current_version": "4.17.20",
        "source": "argus",
        "scanner": "osv",
        "matched_by": ["argus"],
        "match_source": "argus",
    }


def test_finding_from_match_skips_empty_identity():
    # Empty advisory id / package name is malformed -> dropped, not raised.
    item = MatchItem(
        package=MatchPackage(name="", ecosystem="npm"),
        version="4.17.20",
        advisory=MatchAdvisory(id=""),
    )
    assert _finding_from_match(item) is None


def test_match_via_argus_empty_store_returns_empty():
    # The default placeholder store is empty, so no premium findings today.
    assert match_via_argus(_COMPONENTS, asset_id="a1", surface="dependencies") == []


def test_match_via_argus_seeded_store_maps_finding(monkeypatch):
    store = InMemoryPremiumStore([_record()])
    # match_components resolves the store lazily via load_premium_store when none
    # is injected — swap in the seeded store for this call.
    monkeypatch.setattr("src.osv.premium_match.load_premium_store", lambda: store)

    out = match_via_argus(_COMPONENTS, asset_id="a1", surface="dependencies")

    assert len(out) == 1
    f = out[0]
    assert f["source"] == "argus"
    assert f["match_source"] == "argus"
    assert f["matched_by"] == ["argus"]
    assert f["scanner"] == "osv"
    assert f["dependency"]["package"] == {"name": "lodash", "ecosystem": "npm"}
    assert f["current_version"] == "4.17.20"
    assert f["security_advisory"]["ghsa_id"] == "ARGUS-1"
    assert f["security_advisory"]["cve_id"] == "CVE-2099-0001"
    assert f["security_vulnerability"]["first_patched_version"] == {"identifier": "4.17.21"}


def test_match_via_argus_no_components_returns_empty():
    assert match_via_argus([], asset_id="a1", surface="dependencies") == []


# --- Integration: build_backend_match_findings additive wiring ----------------

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


_FREE_BODY = _adv("GHSA-lodash", "npm", "lodash", "4.17.21", cve="CVE-2021-23337")


async def _seed_asset_and_components(factory, asset_id, external_ref):
    async with factory() as s:
        s.add(Asset(
            id=asset_id, type="repo", source="source_connection",
            external_ref=external_ref, display_name="acme/app", asset_metadata={},
        ))
        s.add(SbomComponent(
            asset_id=asset_id, purl="pkg:npm/lodash@4.17.20",
            name="lodash", version="4.17.20", ecosystem="npm",
        ))
        await s.commit()


def _premium_finding(name, version, advisory_id):
    """A premium raw finding as match_via_argus would emit (pre-identity-stamp)."""
    return {
        "repository": {"name": "", "full_name": ""},
        "dependency": {"package": {"name": name, "ecosystem": "npm"}, "manifest_path": ""},
        "security_advisory": {
            "ghsa_id": advisory_id, "cve_id": None, "severity": "high", "cvss": {},
            "summary": "", "description": "", "html_url": "", "references": [], "published_at": "",
        },
        "security_vulnerability": {"vulnerable_version_range": "", "first_patched_version": None},
        "current_version": version,
        "source": "argus", "scanner": "osv", "matched_by": ["argus"], "match_source": "argus",
    }


async def _run_build(factory, asset_id, external_ref, monkeypatch, premium, *, conn_enabled=True):
    """Run the builder with match_via_argus stubbed to ``premium`` and the Argus
    connection lookup stubbed to an ``enabled``/absent connection."""
    def _fake_argus(components, *, asset_id, surface):
        return premium

    async def _fake_fetch(session, key):
        return types.SimpleNamespace(enabled=True) if conn_enabled else None

    monkeypatch.setattr("src.osv.sca_findings.match_via_argus", _fake_argus)
    monkeypatch.setattr("src.osv.sca_findings.fetch_argus_connection", _fake_fetch)
    from src.osv.sca_findings import build_backend_match_findings
    async with factory() as s:
        return await build_backend_match_findings(
            s, asset_id=asset_id, external_ref=external_ref, kind="dependencies",
        )


def _patch_advisory_blob(monkeypatch):
    import json as _json
    monkeypatch.setattr("src.osv.store._upload_blob", lambda *a, **k: None)
    monkeypatch.setattr(
        "src.osv.sca_findings._download_blob",
        lambda key, bucket=None: _json.dumps(_FREE_BODY).encode(),
    )


async def _cleanup(factory, asset_id: str) -> None:
    """Delete the seeded rows so they don't leak into another test's teardown
    (sbom_components has an FK to assets)."""
    async with factory() as session:
        await session.execute(delete(SbomComponent).where(SbomComponent.asset_id == asset_id))
        await session.execute(delete(Asset).where(Asset.id == asset_id))
        await session.commit()


@pytest.mark.asyncio
async def test_build_appends_premium_not_in_free_set(monkeypatch):
    _patch_advisory_blob(monkeypatch)
    store = OsvStore()
    await store.upsert_advisories([_FREE_BODY], ecosystem="npm")

    asset_id = str(uuid.uuid4())
    external_ref = f"github:acme/app-{uuid.uuid4().hex[:8]}"
    engine = create_async_engine(DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        await _seed_asset_and_components(factory, asset_id, external_ref)
        # Premium surfaces a DIFFERENT advisory on the same component.
        premium = [_premium_finding("lodash", "4.17.20", "ARGUS-NEW")]
        raw = await _run_build(factory, asset_id, external_ref, monkeypatch, premium)
    finally:
        await _cleanup(factory, asset_id)
        await engine.dispose()

    advisories = {f["security_advisory"]["ghsa_id"] for f in raw}
    assert advisories == {"GHSA-lodash", "ARGUS-NEW"}
    prem = next(f for f in raw if f["security_advisory"]["ghsa_id"] == "ARGUS-NEW")
    # Caller stamped the repository identity onto the premium finding.
    assert prem["repository"]["full_name"] == external_ref.split(":", 1)[1]
    assert prem["match_source"] == "argus"


@pytest.mark.asyncio
async def test_build_dedups_premium_duplicate_of_free(monkeypatch):
    _patch_advisory_blob(monkeypatch)
    store = OsvStore()
    await store.upsert_advisories([_FREE_BODY], ecosystem="npm")

    asset_id = str(uuid.uuid4())
    external_ref = f"github:acme/app-{uuid.uuid4().hex[:8]}"
    engine = create_async_engine(DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        await _seed_asset_and_components(factory, asset_id, external_ref)
        # Premium returns the SAME component+advisory the free mirror already has.
        premium = [_premium_finding("lodash", "4.17.20", "GHSA-lodash")]
        raw = await _run_build(factory, asset_id, external_ref, monkeypatch, premium)
    finally:
        await _cleanup(factory, asset_id)
        await engine.dispose()

    assert len(raw) == 1
    assert raw[0]["security_advisory"]["ghsa_id"] == "GHSA-lodash"
    # The free finding wins — provenance is not overwritten by the premium dup.
    assert raw[0]["source"] == "backend_match"


@pytest.mark.asyncio
async def test_build_skips_premium_when_connection_disabled(monkeypatch):
    _patch_advisory_blob(monkeypatch)
    store = OsvStore()
    await store.upsert_advisories([_FREE_BODY], ecosystem="npm")

    asset_id = str(uuid.uuid4())
    external_ref = f"github:acme/app-{uuid.uuid4().hex[:8]}"
    engine = create_async_engine(DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        await _seed_asset_and_components(factory, asset_id, external_ref)
        # Even though a premium hit is available, an absent/disabled connection
        # gates it out — only the free finding ships.
        premium = [_premium_finding("lodash", "4.17.20", "ARGUS-NEW")]
        raw = await _run_build(
            factory, asset_id, external_ref, monkeypatch, premium, conn_enabled=False
        )
    finally:
        await _cleanup(factory, asset_id)
        await engine.dispose()

    assert len(raw) == 1
    assert raw[0]["security_advisory"]["ghsa_id"] == "GHSA-lodash"
    assert raw[0]["source"] == "backend_match"
