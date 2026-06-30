"""Tests for the additive Argus premium SBOM match.

Two layers:
- ``match_via_argus`` unit tests with a mocked Argus ``/v1/match`` response and a
  faked token mint — covering the happy path and every degrade-to-empty branch.
- ``build_backend_match_findings`` integration tests proving premium hits are
  appended additively, deduped against the free OSV set, and that an absent /
  failing Argus leaves the free path completely unchanged.
"""
from __future__ import annotations

import uuid

import httpx
import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.db.engine import DATABASE_URL
from src.db.models import Asset, SbomComponent
from src.osv.argus_match import match_via_argus
from src.osv.matcher import ComponentRef
from src.settings.argus.service import ArgusAuthError, ArgusConnectionDTO
from src.osv.store import OsvStore


def _conn(*, enabled: bool = True) -> ArgusConnectionDTO:
    return ArgusConnectionDTO(
        endpoint="https://argus.test/api/",
        token_endpoint="https://argus.test/oauth/token",
        client_id="client-x",
        refresh_token="refresh-x",
        enabled=enabled,
    )


def _argus_match(name="lodash", version="4.17.20", advisory_id="ARGUS-1") -> dict:
    return {
        "purl": f"pkg:npm/{name}@{version}",
        "package": {"name": name, "ecosystem": "npm"},
        "version": version,
        "manifest_path": "package.json",
        "advisory": {
            "id": advisory_id,
            "cve_id": "CVE-2099-0001",
            "severity": "high",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "summary": "premium-only flaw",
            "description": "only in the premium DB",
            "html_url": "https://argus.test/adv/ARGUS-1",
            "references": [{"url": "https://argus.test/ref"}],
            "published_at": "2026-06-01T00:00:00Z",
            "vulnerable_version_range": ">= 0, < 4.17.21",
            "first_patched_version": "4.17.21",
        },
    }


class _FakeResponse:
    def __init__(self, status_code: int, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _FakeAsyncClient:
    """Stand-in for ``httpx.AsyncClient`` as an async context manager."""

    def __init__(self, response=None, raise_exc=None):
        self._response = response
        self._raise = raise_exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, *args, **kwargs):
        if self._raise is not None:
            raise self._raise
        return self._response


def _patch_client(monkeypatch, *, response=None, raise_exc=None):
    monkeypatch.setattr(
        "src.osv.argus_match.httpx.AsyncClient",
        lambda *a, **k: _FakeAsyncClient(response=response, raise_exc=raise_exc),
    )


def _patch_mint(monkeypatch, token="tok-123"):
    monkeypatch.setattr(
        "src.osv.argus_match.mint_argus_access_token", lambda conn: token
    )


_COMPONENTS = [ComponentRef(name="lodash", version="4.17.20", purl_type="npm",
                            purl="pkg:npm/lodash@4.17.20")]


@pytest.mark.asyncio
async def test_match_via_argus_maps_premium_hit(monkeypatch):
    _patch_mint(monkeypatch)
    _patch_client(monkeypatch, response=_FakeResponse(200, {"matches": [_argus_match()]}))

    out = await match_via_argus(_conn(), _COMPONENTS, asset_id="a1", surface="dependencies")

    assert len(out) == 1
    f = out[0]
    assert f["source"] == "argus"
    assert f["match_source"] == "argus"
    assert f["matched_by"] == ["argus"]
    assert f["scanner"] == "osv"
    assert f["dependency"]["package"] == {"name": "lodash", "ecosystem": "npm"}
    assert f["dependency"]["manifest_path"] == "package.json"
    assert f["current_version"] == "4.17.20"
    assert f["security_advisory"]["ghsa_id"] == "ARGUS-1"
    assert f["security_advisory"]["cve_id"] == "CVE-2099-0001"
    assert f["security_advisory"]["severity"] == "high"
    assert f["security_advisory"]["references"] == [{"url": "https://argus.test/ref"}]
    assert f["security_vulnerability"]["first_patched_version"] == {"identifier": "4.17.21"}


@pytest.mark.asyncio
async def test_match_via_argus_unconfigured_returns_empty(monkeypatch):
    _patch_mint(monkeypatch)
    _patch_client(monkeypatch, response=_FakeResponse(200, {"matches": [_argus_match()]}))

    assert await match_via_argus(None, _COMPONENTS, asset_id="a", surface="dependencies") == []


@pytest.mark.asyncio
async def test_match_via_argus_disabled_returns_empty(monkeypatch):
    _patch_mint(monkeypatch)
    _patch_client(monkeypatch, response=_FakeResponse(200, {"matches": [_argus_match()]}))

    out = await match_via_argus(
        _conn(enabled=False), _COMPONENTS, asset_id="a", surface="dependencies"
    )
    assert out == []


@pytest.mark.asyncio
async def test_match_via_argus_transport_error_returns_empty(monkeypatch):
    _patch_mint(monkeypatch)
    _patch_client(monkeypatch, raise_exc=httpx.ConnectError("down"))

    out = await match_via_argus(_conn(), _COMPONENTS, asset_id="a", surface="dependencies")
    assert out == []


@pytest.mark.asyncio
async def test_match_via_argus_non_200_returns_empty(monkeypatch):
    _patch_mint(monkeypatch)
    _patch_client(monkeypatch, response=_FakeResponse(503, {"matches": []}))

    out = await match_via_argus(_conn(), _COMPONENTS, asset_id="a", surface="dependencies")
    assert out == []


@pytest.mark.asyncio
async def test_match_via_argus_auth_error_returns_empty(monkeypatch):
    def _boom(conn):
        raise ArgusAuthError("nope")

    monkeypatch.setattr("src.osv.argus_match.mint_argus_access_token", _boom)
    # If mint failed, the HTTP call must never fire.
    _patch_client(monkeypatch, raise_exc=AssertionError("should not POST"))

    out = await match_via_argus(_conn(), _COMPONENTS, asset_id="a", surface="dependencies")
    assert out == []


@pytest.mark.asyncio
async def test_match_via_argus_skips_malformed_entries(monkeypatch):
    _patch_mint(monkeypatch)
    payload = {"matches": [
        {"package": {"name": "x"}},          # no version / advisory -> skipped
        "garbage",                            # not a dict -> skipped
        _argus_match(),                       # valid
    ]}
    _patch_client(monkeypatch, response=_FakeResponse(200, payload))

    out = await match_via_argus(_conn(), _COMPONENTS, asset_id="a", surface="dependencies")
    assert len(out) == 1


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


async def _run_build(factory, asset_id, external_ref, monkeypatch, premium):
    """Run the builder with match_via_argus stubbed to ``premium``."""
    async def _fake_argus(conn, components, *, asset_id, surface):
        return premium

    monkeypatch.setattr("src.osv.sca_findings.match_via_argus", _fake_argus)
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
async def test_build_unchanged_when_argus_absent(monkeypatch):
    _patch_advisory_blob(monkeypatch)
    store = OsvStore()
    await store.upsert_advisories([_FREE_BODY], ecosystem="npm")

    asset_id = str(uuid.uuid4())
    external_ref = f"github:acme/app-{uuid.uuid4().hex[:8]}"
    engine = create_async_engine(DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        await _seed_asset_and_components(factory, asset_id, external_ref)
        raw = await _run_build(factory, asset_id, external_ref, monkeypatch, [])  # Argus degraded
    finally:
        await _cleanup(factory, asset_id)
        await engine.dispose()

    assert len(raw) == 1
    assert raw[0]["security_advisory"]["ghsa_id"] == "GHSA-lodash"
    assert raw[0]["source"] == "backend_match"
