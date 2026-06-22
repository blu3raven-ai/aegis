"""Tests for in-backend OSV reconcile (re-matching SBOMs on catalog change)."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.db.engine import DATABASE_URL
from src.db.models import Asset, SbomComponent
from src.osv.rematch import _affected_asset_ids, _group_key, reconcile_sbom_matches
from src.osv.store import OsvStore


# ── _group_key (pure) ───────────────────────────────────────────────────────

def test_group_key_repo():
    assert _group_key("github:acme/app", "repo") == ("dependencies_scanning", "github", "acme", "dependencies")


def test_group_key_image():
    assert _group_key("ghcr:acme/app:1.2.3", "image") == ("container_scanning", "ghcr", "acme", "container")


def test_group_key_unsupported_type_or_ref():
    assert _group_key("github:acme/app", "secret") is None
    assert _group_key("noscheme", "repo") is None
    assert _group_key("github:noslash", "repo") is None


# ── DB-backed reconcile ─────────────────────────────────────────────────────

def _adv(adv_id, ecosystem, name, fixed):
    return {
        "id": adv_id, "summary": f"{name}", "details": "",
        "aliases": [], "severity": [], "database_specific": {"severity": "HIGH"},
        "references": [], "published": "2026-06-01T00:00:00Z", "modified": "2026-06-10T00:00:00Z",
        "affected": [{
            "package": {"name": name, "ecosystem": ecosystem},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
        }],
    }


async def _new_session():
    engine = create_async_engine(DATABASE_URL, echo=False)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


@pytest.mark.asyncio
async def test_reconcile_rematches_only_affected_group(monkeypatch):
    store = OsvStore()
    monkeypatch.setattr("src.osv.store._upload_blob", lambda *a, **k: None)
    monkeypatch.setattr(
        "src.osv.sca_findings._download_blob",
        lambda key, bucket=None: b"{}",
    )
    # Unique package + org so this test never collides with other tests'
    # data in the shared dev DB (raw inserts have no per-test rollback).
    await store.upsert_advisories(
        [_adv("GHSA-rematchpkg", "npm", "rematchpkg", "2.0.0")], ecosystem="npm"
    )

    affected_id = str(uuid.uuid4())
    other_id = str(uuid.uuid4())
    engine, factory = await _new_session()
    try:
        async with factory() as s:
            s.add(Asset(id=affected_id, type="repo", source="source_connection",
                        external_ref="github:rematchorg/affected", display_name="rematchorg/affected", asset_metadata={}))
            s.add(Asset(id=other_id, type="repo", source="source_connection",
                        external_ref="github:rematchorg/clean", display_name="rematchorg/clean", asset_metadata={}))
            s.add(SbomComponent(asset_id=affected_id, purl="pkg:npm/rematchpkg@1.0.0",
                                name="rematchpkg", version="1.0.0", ecosystem="npm"))
            s.add(SbomComponent(asset_id=other_id, purl="pkg:npm/rematchclean@1.0.0",
                                name="rematchclean", version="1.0.0", ecosystem="npm"))
            await s.commit()

            affected = await _affected_asset_ids(s, ["GHSA-rematchpkg"])
            assert affected == {affected_id}
    finally:
        await engine.dispose()

    # Stub apply_lifecycle to capture calls without the heavy persistence path.
    calls: list[tuple] = []
    monkeypatch.setattr(
        "src.shared.lifecycle.apply_lifecycle",
        lambda hooks, ctx, findings: calls.append((ctx.tool, ctx.org, ctx.source_type, len(findings))),
    )

    count = await reconcile_sbom_matches(["GHSA-rematchpkg"])

    # The affected group (rematchorg) is re-matched as a whole: the vulnerable
    # asset produces a finding, the clean one in the same group produces none.
    assert count == 1
    assert len(calls) == 1
    assert calls[0] == ("dependencies_scanning", "rematchorg", "github", 1)


@pytest.mark.asyncio
async def test_reconcile_empty_changed_set_noops(monkeypatch):
    called = []
    monkeypatch.setattr("src.shared.lifecycle.apply_lifecycle",
                        lambda *a, **k: called.append(1))
    assert await reconcile_sbom_matches([]) == 0
    assert called == []
