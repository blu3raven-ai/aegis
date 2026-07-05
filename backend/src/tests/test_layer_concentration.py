from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

import pytest  # noqa: E402
from sqlalchemy import delete  # noqa: E402

from src.db.models import Asset, Finding  # noqa: E402
from src.findings.service import layer_concentration  # noqa: E402


async def _mk_image_asset(db_session) -> str:
    aid = str(uuid4())
    db_session.add(Asset(
        id=aid, type="image", source="source_connection",
        external_ref=f"ghcr:acme/{uuid4().hex}", display_name="acme/app", asset_metadata={},
    ))
    await db_session.commit()
    return aid


def _container_finding(asset_id: str, layer_index: int | None, state: str = "open") -> Finding:
    detail = {"imageDigest": "sha256:img"}
    if layer_index is not None:
        detail["layerIndex"] = str(layer_index)
    return Finding(
        tool="container_scanning",
        identity_key=f"lc-{uuid4()}",
        state=state,
        severity="high",
        asset_id=asset_id,
        detail=detail,
    )


@pytest.mark.asyncio
async def test_returns_most_affected_layer(db_session):
    aid = await _mk_image_asset(db_session)
    findings = [
        _container_finding(aid, 0),
        _container_finding(aid, 0),
        _container_finding(aid, 0),
        _container_finding(aid, 2),
        _container_finding(aid, 5, state="fixed"),  # not open — excluded
        _container_finding(aid, None),               # no layer — excluded
    ]
    db_session.add_all(findings)
    await db_session.commit()
    try:
        result = await layer_concentration(findings[0], db_session)
        assert result == {"layer_index": 0, "finding_count": 3, "total_with_layer": 4}
    finally:
        await db_session.execute(delete(Finding).where(Finding.id.in_([f.id for f in findings])))
        await db_session.execute(delete(Asset).where(Asset.id == aid))
        await db_session.commit()


@pytest.mark.asyncio
async def test_none_for_non_container_finding(db_session):
    f = Finding(tool="dependencies_scanning", identity_key=f"lc-{uuid4()}", state="open",
                severity="high", asset_id=None, detail={})
    db_session.add(f)
    await db_session.commit()
    try:
        assert await layer_concentration(f, db_session) is None
    finally:
        await db_session.execute(delete(Finding).where(Finding.id == f.id))
        await db_session.commit()


@pytest.mark.asyncio
async def test_none_when_no_layer_attributed_findings(db_session):
    aid = await _mk_image_asset(db_session)
    f = _container_finding(aid, None)
    db_session.add(f)
    await db_session.commit()
    try:
        assert await layer_concentration(f, db_session) is None
    finally:
        await db_session.execute(delete(Finding).where(Finding.id == f.id))
        await db_session.execute(delete(Asset).where(Asset.id == aid))
        await db_session.commit()
