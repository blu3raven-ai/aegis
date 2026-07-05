"""upsert_sbom appends an idempotent sbom_runs row per scan run, feeding the
indexed history resolver."""
from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import delete, select

from src.db.models import Asset, Sbom, SbomRun
from src.dependencies.sbom_store import upsert_sbom
from src.sbom.resolvers import sbom_history


async def _mk_asset(db_session) -> str:
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type="repo", source="source_connection",
        external_ref=f"github:acme/{uuid.uuid4().hex}", display_name="acme/api",
    ))
    await db_session.commit()
    return aid


async def _cleanup(db_session, aid: str) -> None:
    await db_session.execute(delete(SbomRun).where(SbomRun.asset_id == aid))
    await db_session.execute(delete(Sbom).where(Sbom.asset_id == aid))
    await db_session.execute(delete(Asset).where(Asset.id == aid))
    await db_session.commit()


@pytest.mark.asyncio
async def test_upsert_records_idempotent_run_history(db_session):
    aid = await _mk_asset(db_session)
    sbom = {"components": []}
    try:
        with patch("src.dependencies.sbom_store.upload_to_minio"), \
             patch("src.dependencies.sbom_store.populate_components", return_value=0):
            upsert_sbom(org="acme", repo="api", commit_sha="c1", sbom=sbom,
                        manifests={}, run_id="auto-1", asset_id=aid)
            # Re-ingesting the same run updates in place, never duplicates.
            upsert_sbom(org="acme", repo="api", commit_sha="c2", sbom=sbom,
                        manifests={}, run_id="auto-1", asset_id=aid)
            # A new run appends a second history row.
            upsert_sbom(org="acme", repo="api", commit_sha="c3", sbom=sbom,
                        manifests={}, run_id="auto-2", asset_id=aid)

        rows = (await db_session.execute(
            select(SbomRun.run_id, SbomRun.commit_sha)
            .where(SbomRun.asset_id == aid)
            .order_by(SbomRun.run_id)
        )).all()
        assert [r.run_id for r in rows] == ["auto-1", "auto-2"]
        by = {r.run_id: r.commit_sha for r in rows}
        assert by["auto-1"] == "c2"  # same-run re-ingest updated the row
        assert by["auto-2"] == "c3"

        # The latest single Sbom row tracks the most recent run.
        latest = (await db_session.execute(
            select(Sbom.run_id).where(Sbom.asset_id == aid)
        )).scalar_one()
        assert latest == "auto-2"

        # The history resolver reads these rows, newest-first.
        history = sbom_history(repo="acme/api", limit=10, info_context={"asset_ids": [aid]})
        assert [e.run_id for e in history] == ["auto-2", "auto-1"]
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_upsert_persists_and_overwrites_html_url(db_session):
    aid = await _mk_asset(db_session)
    sbom = {"components": []}
    try:
        with patch("src.dependencies.sbom_store.upload_to_minio"), \
             patch("src.dependencies.sbom_store.populate_components", return_value=0):
            upsert_sbom(org="acme", repo="api", commit_sha="c1", sbom=sbom,
                        manifests={}, run_id="run-1", asset_id=aid,
                        html_url="https://ghe.acme-corp.internal/acme/api")
        stored = (await db_session.execute(
            select(Sbom.html_url).where(Sbom.asset_id == aid)
        )).scalar_one()
        assert stored == "https://ghe.acme-corp.internal/acme/api"

        # Re-ingest without a URL overwrites in place (mirrors commit_sha).
        with patch("src.dependencies.sbom_store.upload_to_minio"), \
             patch("src.dependencies.sbom_store.populate_components", return_value=0):
            upsert_sbom(org="acme", repo="api", commit_sha="c2", sbom=sbom,
                        manifests={}, run_id="run-1", asset_id=aid)
        assert (await db_session.execute(
            select(Sbom.html_url).where(Sbom.asset_id == aid)
        )).scalar_one() is None
    finally:
        await _cleanup(db_session, aid)
