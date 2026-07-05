"""A container image digest can be shared across tenants; the by-digest fetch
must resolve to the caller's own in-scope row, not whichever row an unscoped
LIMIT 1 happens to return (which would diff/export as a spurious 404)."""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from unittest.mock import patch  # noqa: E402

from sqlalchemy import delete  # noqa: E402

from src.db.models import Asset, Sbom  # noqa: E402
from src.sbom.resolvers import _fetch_container_sbom_by_digest as resolver_fetch  # noqa: E402
from src.sbom.router import _fetch_container_sbom_by_digest as router_fetch  # noqa: E402

_DIGEST = "sha256:" + "c" * 64
_FAKE_SBOM = {"bomFormat": "CycloneDX", "components": []}


async def _seed_shared_digest(db_session) -> tuple[str, str]:
    """Two image assets in different tenants, both carrying the same digest."""
    a = str(uuid.uuid4())
    b = str(uuid.uuid4())
    db_session.add_all([
        Asset(id=a, type="image", source="source_connection",
              external_ref=f"ghcr:acme-org/{uuid.uuid4().hex}:latest", display_name="acme-org/img"),
        Asset(id=b, type="image", source="source_connection",
              external_ref=f"ghcr:other-org/{uuid.uuid4().hex}:latest", display_name="other-org/img"),
    ])
    await db_session.flush()
    db_session.add_all([
        Sbom(asset_id=a, commit_sha=_DIGEST, s3_key=f"{a}/sbom.cdx.json", run_id="r-a"),
        Sbom(asset_id=b, commit_sha=_DIGEST, s3_key=f"{b}/sbom.cdx.json", run_id="r-b"),
    ])
    await db_session.commit()
    return a, b


async def _cleanup(db_session, *asset_ids: str) -> None:
    for aid in asset_ids:
        await db_session.execute(delete(Sbom).where(Sbom.asset_id == aid))
        await db_session.execute(delete(Asset).where(Asset.id == aid))
    await db_session.commit()


@pytest.mark.asyncio
async def test_router_fetch_resolves_callers_own_row(db_session):
    a, b = await _seed_shared_digest(db_session)
    try:
        with patch("src.sbom.router.download_from_minio", return_value=_FAKE_SBOM):
            # Caller scoped to A gets A's row even though B shares the digest.
            sbom, reason, asset_id = router_fetch(_DIGEST, [a])
            assert reason is None and asset_id == a
            # Caller scoped to B gets B's row.
            _, _, asset_id_b = router_fetch(_DIGEST, [b])
            assert asset_id_b == b
            # No scope → fail-closed no_row, never another tenant's data.
            assert router_fetch(_DIGEST, []) == (None, "no_row", None)
            assert router_fetch(_DIGEST, [str(uuid.uuid4())]) == (None, "no_row", None)
    finally:
        await _cleanup(db_session, a, b)


@pytest.mark.asyncio
async def test_resolver_fetch_resolves_callers_own_row(db_session):
    a, b = await _seed_shared_digest(db_session)
    try:
        with patch("src.sbom.resolvers.download_from_minio", return_value=_FAKE_SBOM):
            sbom, asset_id = resolver_fetch(_DIGEST, [a])
            assert asset_id == a
            assert resolver_fetch(_DIGEST, []) == (None, None)
            assert resolver_fetch(_DIGEST, [str(uuid.uuid4())]) == (None, None)
    finally:
        await _cleanup(db_session, a, b)
