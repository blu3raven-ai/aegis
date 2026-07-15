"""Hardening of the SBOM surface against malformed / corrupt input.

A security product ingests and re-serves SBOMs produced by external scanners,
so a corrupt blob or a non-string field must degrade gracefully (clean 404 /
skip) rather than 500 or silently drop a whole asset's inventory.
"""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from unittest.mock import MagicMock, patch  # noqa: E402

from sqlalchemy import delete, select  # noqa: E402

from src.db.models import Asset, Sbom, SbomComponent  # noqa: E402
from src.sbom.exporter import SbomExporter  # noqa: E402
from src.sbom.storage import populate_components  # noqa: E402


# ── Corrupt-blob tolerance in the download helpers ──────────────────────────


def test_download_json_returns_none_on_corrupt_blob():
    from src.shared import object_store

    with patch.object(object_store, "download_bytes", return_value=b'{"components": ['):
        assert object_store.download_json("k") is None


def test_download_from_minio_returns_none_on_corrupt_blob():
    from src.sbom import storage

    fake_client = MagicMock()
    fake_client.get_object.return_value = {"Body": MagicMock(read=lambda: b"not json {{{")}
    with patch.object(storage, "get_s3_client", return_value=fake_client):
        assert storage.download_from_minio("k") is None


# ── Exporter coercion / non-dict guards (XML serializer is the crash path) ──


def _bad_sbom() -> dict:
    # Numeric version/type, a non-dict component, and a non-dict license entry —
    # all of which ElementTree would refuse without coercion.
    return {
        "specVersion": "1.5",
        "serialNumber": 12345,
        "version": 2,
        "metadata": {"timestamp": 1700000000, "tools": [{"name": "syft", "version": 1.4}, "junk"]},
        "components": [
            {"name": "left", "version": 1.4, "type": 7, "purl": "pkg:npm/left",
             "licenses": [{"license": {"id": "MIT"}}, "junk-license"]},
            "not-a-dict-component",
        ],
        "dependencies": [{"ref": "a", "dependsOn": ["b"]}, "junk-dep"],
    }


def test_xml_export_coerces_non_string_fields_without_crashing():
    out = SbomExporter().export(_bad_sbom(), "cyclonedx-xml")
    assert out.startswith("<?xml")
    assert "left" in out and "1.4" in out  # numeric version coerced to text


def test_spdx_exports_tolerate_malformed_components():
    bad = _bad_sbom()
    sj = SbomExporter().export(bad, "spdx-json")
    assert "SPDXRef-DOCUMENT" in sj
    tv = SbomExporter().export(bad, "spdx-tag-value")
    assert "SPDXVersion:" in tv


# ── populate_components: pure-guard early returns (no DB) ────────────────────


def test_populate_components_non_dict_sbom_returns_zero():
    assert populate_components("org", "repo", ["not", "a", "dict"], asset_id="x") == 0  # type: ignore[arg-type]


def test_populate_components_non_list_components_returns_zero():
    assert populate_components("org", "repo", {"components": "nope"}, asset_id="x") == 0


# ── populate_components: a non-dict entry skips just that row (DB-backed) ────


async def _mk_asset(db_session) -> str:
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/api",
    ))
    await db_session.commit()
    return aid


async def _cleanup(db_session, aid: str) -> None:
    await db_session.execute(delete(SbomComponent).where(SbomComponent.asset_id == aid))
    await db_session.execute(delete(Sbom).where(Sbom.asset_id == aid))
    await db_session.execute(delete(Asset).where(Asset.id == aid))
    await db_session.commit()


@pytest.mark.asyncio
async def test_non_dict_component_skips_row_not_whole_asset(db_session):
    # One junk entry alongside valid components must NOT abort indexing the whole
    # asset (which would silently drop its inventory + downstream SCA findings).
    aid = await _mk_asset(db_session)
    sbom = {
        "components": [
            "junk-string",
            {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
            12345,
            {"name": "axios", "version": "1.6.0", "purl": "pkg:npm/axios@1.6.0"},
        ],
    }
    try:
        populate_components("acme-org", "api", sbom, asset_id=aid)
        names = {
            n for (n,) in (await db_session.execute(
                select(SbomComponent.name).where(SbomComponent.asset_id == aid)
            )).all()
        }
        assert names == {"lodash", "axios"}
    finally:
        await _cleanup(db_session, aid)
