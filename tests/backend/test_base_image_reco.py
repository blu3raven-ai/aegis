from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

import pytest  # noqa: E402
from sqlalchemy import delete  # noqa: E402

from src.containers.base_image_reco import build_candidate_ref, pick_recommendation  # noqa: E402


def test_build_candidate_ref_swaps_trailing_tag():
    assert build_candidate_ref("ghcr.io/acme/app:1.2.3", "2.0.0") == "ghcr.io/acme/app:2.0.0"
    # registry host:port colon is not the tag separator
    assert build_candidate_ref("reg:5000/acme/app:1.0", "2.0") == "reg:5000/acme/app:2.0"
    # digest dropped
    assert build_candidate_ref("ghcr.io/acme/app:1.0@sha256:abc", "2.0") == "ghcr.io/acme/app:2.0"
    # no tag → append
    assert build_candidate_ref("ghcr.io/acme/app", "2.0") == "ghcr.io/acme/app:2.0"


def test_pick_recommendation_prefers_fewest_vulns_below_current():
    assert pick_recommendation(14, {"2.0.0": 2, "1.9.0": 6}) == ("2.0.0", 2)


def test_pick_recommendation_none_when_no_improvement():
    assert pick_recommendation(3, {"2.0.0": 3, "1.9.0": 5}) is None
    assert pick_recommendation(0, {}) is None


def test_pick_recommendation_tie_breaks_to_higher_tag():
    # Equal counts → deterministic pick of the lexicographically larger tag.
    assert pick_recommendation(10, {"2.0.0": 4, "1.9.0": 4}) == ("2.0.0", 4)


@pytest.mark.asyncio
async def test_recommendation_service_reads_positive_row(db_session):
    from src.db.models import BaseImageRecommendation
    from src.findings.service import base_image_recommendation

    digest = f"sha256:{uuid4().hex}"
    db_session.add(BaseImageRecommendation(
        image_digest=digest, current_ref="ghcr.io/acme/app:1.0", current_vuln_count=14,
        recommended_tag="2.0.0", recommended_vuln_count=2, candidates_scanned=1,
        computed_at=datetime.now(timezone.utc),
    ))
    await db_session.commit()
    try:
        result = await base_image_recommendation(digest, db_session)
        assert result == {
            "recommended_tag": "2.0.0",
            "current_vuln_count": 14,
            "recommended_vuln_count": 2,
        }
        assert await base_image_recommendation(None, db_session) is None
        assert await base_image_recommendation("sha256:absent", db_session) is None
    finally:
        await db_session.execute(
            delete(BaseImageRecommendation).where(BaseImageRecommendation.image_digest == digest)
        )
        await db_session.commit()


@pytest.mark.asyncio
async def test_recommendation_service_hides_negative_row(db_session):
    from src.db.models import BaseImageRecommendation
    from src.findings.service import base_image_recommendation

    digest = f"sha256:{uuid4().hex}"
    db_session.add(BaseImageRecommendation(
        image_digest=digest, current_ref="ghcr.io/acme/app:1.0", current_vuln_count=3,
        recommended_tag=None, recommended_vuln_count=None, candidates_scanned=1,
        computed_at=datetime.now(timezone.utc),
    ))
    await db_session.commit()
    try:
        # A cached "nothing improves" negative surfaces as no recommendation.
        assert await base_image_recommendation(digest, db_session) is None
    finally:
        await db_session.execute(
            delete(BaseImageRecommendation).where(BaseImageRecommendation.image_digest == digest)
        )
        await db_session.commit()
