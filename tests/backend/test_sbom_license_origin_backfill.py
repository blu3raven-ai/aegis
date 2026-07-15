"""The license/origin backfill re-classifies existing SBOM components from their
stored CycloneDX blob, fail-safe on missing/empty blobs, preserving scan time."""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from unittest.mock import patch  # noqa: E402

from sqlalchemy import delete, select  # noqa: E402

import src.sbom.license_origin_backfill as bf  # noqa: E402
from src.db.models import Asset, Sbom, SbomComponent  # noqa: E402

_SCANNED = datetime(2026, 1, 1, tzinfo=timezone.utc)


async def _seed(db_session, *, atype: str, s3_key: str, display: str) -> str:
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type=atype, source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name=display,
    ))
    await db_session.flush()
    db_session.add(Sbom(asset_id=aid, commit_sha="HEAD", s3_key=s3_key, run_id="r1", scanned_at=_SCANNED))
    await db_session.commit()
    return aid


async def _rows(db_session, aid: str):
    return (await db_session.execute(
        select(SbomComponent.name, SbomComponent.is_direct, SbomComponent.license_category,
               SbomComponent.source_tool, SbomComponent.scanned_at)
        .where(SbomComponent.asset_id == aid)
    )).all()


async def _cleanup(db_session, *aids: str) -> None:
    for aid in aids:
        await db_session.execute(delete(SbomComponent).where(SbomComponent.asset_id == aid))
        await db_session.execute(delete(Sbom).where(Sbom.asset_id == aid))
        await db_session.execute(delete(Asset).where(Asset.id == aid))
    await db_session.commit()


_REPO_BLOB = {
    "metadata": {"component": {"bom-ref": "root", "type": "application"}},
    "components": [
        {"name": "lodash", "version": "4.0.0", "purl": "pkg:npm/lodash@4.0.0",
         "bom-ref": "r-lod", "licenses": [{"license": {"id": "MIT"}}]},
        {"name": "gpl-lib", "version": "1.0", "purl": "pkg:npm/gpl-lib@1.0",
         "bom-ref": "r-gpl", "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
    ],
    "dependencies": [{"ref": "root", "dependsOn": ["r-lod"]}],  # gpl-lib is orphan
}

_IMAGE_BLOB = {
    "metadata": {"component": {"bom-ref": "img", "type": "container"}},
    "components": [{"name": "openssl", "version": "3.0", "purl": "pkg:apk/openssl@3.0", "bom-ref": "r-ssl"}],
    "dependencies": [{"ref": "img", "dependsOn": ["r-ssl"]}],
}


@pytest.mark.asyncio
async def test_backfill_repo_classifies_license_and_origin(db_session):
    aid = await _seed(db_session, atype="repo", s3_key="k-repo", display="acme-org/api")
    try:
        with patch.object(bf, "download_from_minio", return_value=_REPO_BLOB):
            stats = bf.backfill_all()
        by = {n: (d, c, st, sa) for n, d, c, st, sa in await _rows(db_session, aid)}
        assert by["lodash"][0] is True and by["lodash"][1] == "permissive"   # direct + permissive
        assert by["gpl-lib"][0] is None and by["gpl-lib"][1] == "copyleft"   # orphan -> unknown, GPL
        # scanned_at preserved from the Sbom row, not reset to now().
        assert by["lodash"][3] == _SCANNED
        assert stats.reindexed >= 1 and stats.errored == 0
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_backfill_image_uses_syft_tool_and_unknown_origin(db_session):
    aid = await _seed(db_session, atype="image", s3_key="k-img", display="acme-org/img")
    try:
        with patch.object(bf, "download_from_minio", return_value=_IMAGE_BLOB):
            bf.backfill_all()
        by = {n: (d, c, st) for n, d, c, st, _ in await _rows(db_session, aid)}
        assert by["openssl"][0] is None       # container root -> origin unknown
        assert by["openssl"][2] == "syft"     # image wrapper stamped source_tool
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_backfill_missing_blob_is_failsafe_skip(db_session):
    aid = await _seed(db_session, atype="repo", s3_key="gone", display="acme-org/x")
    # Pre-existing row must SURVIVE a missing-blob skip (no delete).
    db_session.add(SbomComponent(asset_id=aid, purl="pkg:npm/keep@1", name="keep", version="1", ecosystem="npm"))
    await db_session.commit()
    try:
        with patch.object(bf, "download_from_minio", return_value=None):
            stats = bf.backfill_all()
        assert stats.skipped_no_blob == 1 and stats.reindexed == 0
        assert [n for n, *_ in await _rows(db_session, aid)] == ["keep"]  # not wiped
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_backfill_dry_run_writes_nothing(db_session):
    aid = await _seed(db_session, atype="repo", s3_key="k-dry", display="acme-org/dry")
    try:
        with patch.object(bf, "download_from_minio", return_value=_REPO_BLOB):
            stats = bf.backfill_all(dry_run=True)
        assert stats.reindexed == 1 and stats.components_indexed == 2
        assert await _rows(db_session, aid) == []  # nothing written
    finally:
        await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_backfill_isolates_per_asset_failure(db_session):
    good = await _seed(db_session, atype="repo", s3_key="k-good", display="acme-org/good")
    bad = await _seed(db_session, atype="repo", s3_key="k-bad", display="acme-org/bad")
    try:
        def fake_dl(key):
            if key == "k-bad":
                raise RuntimeError("corrupt blob")
            return _REPO_BLOB
        with patch.object(bf, "download_from_minio", side_effect=fake_dl):
            stats = bf.backfill_all()
        assert stats.errored == 1 and stats.reindexed == 1  # bad isolated, good still done
        assert len(await _rows(db_session, good)) == 2
    finally:
        await _cleanup(db_session, good, bad)
