"""DB-backed coverage for findings/service blast-radius + base-image queries."""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.db.models import Asset, BaseImageRecommendation, Finding  # noqa: E402
from src.findings.service import (  # noqa: E402
    _related_match,
    base_image_recommendation,
    count_related_repos,
)


def _finding(asset_id, *, cve=None, pkg=None, state="open"):
    return Finding(
        tool="dependencies_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=asset_id,
        state=state, severity="high", title="x", cve_id=cve, package_name=pkg, archived=False,
    )


def test_related_match_prefers_cve_then_package():
    assert _related_match(_finding("a", cve="CVE-1", pkg="lodash")) is not None  # CVE branch
    assert _related_match(_finding("a", pkg="lodash")) is not None              # package branch
    assert _related_match(_finding("a")) is None                                 # neither


async def _asset(db_session):
    aid = str(uuid.uuid4())
    db_session.add(Asset(
        id=aid, type="repo", source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}", display_name="acme-org/x",
    ))
    return aid


@pytest.mark.asyncio
async def test_count_related_repos_counts_other_active_in_scope_assets(db_session):
    a, b, c = await _asset(db_session), await _asset(db_session), await _asset(db_session)
    subject = _finding(a, cve="CVE-2026-9")
    db_session.add(subject)
    db_session.add(_finding(b, cve="CVE-2026-9"))              # other asset, active → counts
    db_session.add(_finding(c, cve="CVE-2026-9", state="fixed"))  # inactive → excluded
    db_session.add(_finding(a, cve="CVE-2026-9"))              # same asset as subject → excluded
    await db_session.flush()

    n = await count_related_repos(subject, [a, b, c], db_session)
    assert n == 1  # only asset b


@pytest.mark.asyncio
async def test_count_related_repos_zero_without_scope_or_match(db_session):
    a = await _asset(db_session)
    assert await count_related_repos(_finding(a, cve="CVE-1"), [], db_session) == 0   # no scope
    assert await count_related_repos(_finding(a), [a], db_session) == 0               # no cve/pkg


@pytest.mark.asyncio
async def test_base_image_recommendation_returns_row_or_none(db_session):
    assert await base_image_recommendation(None, db_session) is None
    assert await base_image_recommendation("sha256:missing", db_session) is None

    digest = f"sha256:{uuid.uuid4().hex}"
    db_session.add(BaseImageRecommendation(
        image_digest=digest, current_ref="python:3.18", recommended_tag="3.19-slim",
        current_vuln_count=10, recommended_vuln_count=2,
    ))
    await db_session.flush()
    rec = await base_image_recommendation(digest, db_session)
    assert rec == {"recommended_tag": "3.19-slim", "current_vuln_count": 10, "recommended_vuln_count": 2}


@pytest.mark.asyncio
async def test_base_image_recommendation_none_when_no_better_tag(db_session):
    digest = f"sha256:{uuid.uuid4().hex}"
    db_session.add(BaseImageRecommendation(image_digest=digest, current_ref="python:3.18", recommended_tag=""))
    await db_session.flush()
    assert await base_image_recommendation(digest, db_session) is None
