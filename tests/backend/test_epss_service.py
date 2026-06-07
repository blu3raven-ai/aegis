"""Tests for EpssService.

EpssService uses run_db() internally (like kev/service.py), so tests call
the synchronous methods directly — no async wrangling needed.
"""
from __future__ import annotations

from datetime import date

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sample_rows(n: int = 3, prefix: str = "") -> list[dict]:
    today = date.today()
    rows = []
    for i in range(n):
        rows.append({
            "cve": f"CVE-2024-SVC{prefix}{20000 + i}",
            "score": 0.1 + (i * 0.1),
            "percentile": 0.5 + (i * 0.05),
            "scored_date": today,
        })
    return rows


# ---------------------------------------------------------------------------
# upsert_scores
# ---------------------------------------------------------------------------


def test_upsert_returns_new_count():
    """First upsert of N rows returns N (all are new)."""
    from src.epss.service import EpssService
    service = EpssService()
    rows = _sample_rows(3, prefix="A")
    new_count = service.upsert_scores(rows)
    assert new_count == 3


def test_upsert_idempotent():
    """Re-upserting the same rows returns 0 new rows."""
    from src.epss.service import EpssService
    service = EpssService()
    rows = _sample_rows(2, prefix="B")
    service.upsert_scores(rows)
    new_count = service.upsert_scores(rows)
    assert new_count == 0


def test_upsert_updates_existing_score():
    """Upsert with a changed score updates the row in place."""
    from src.epss.service import EpssService
    service = EpssService()
    cve = "CVE-2024-SVC88001"
    original = {
        "cve": cve,
        "score": 0.10,
        "percentile": 0.20,
        "scored_date": date(2024, 1, 1),
    }
    service.upsert_scores([original])

    updated = {**original, "score": 0.99, "percentile": 0.999, "scored_date": date(2024, 5, 13)}
    service.upsert_scores([updated])

    score = service.get_score(cve)
    assert score is not None
    assert score.score == pytest.approx(0.99)
    assert score.percentile == pytest.approx(0.999)
    assert score.scored_date == date(2024, 5, 13)


def test_upsert_empty_iterable_returns_zero():
    from src.epss.service import EpssService
    service = EpssService()
    assert service.upsert_scores([]) == 0
    assert service.upsert_scores(iter([])) == 0


def test_upsert_accepts_generator():
    """Upsert must work with any iterable, not just lists."""
    from src.epss.service import EpssService
    service = EpssService()
    rows = _sample_rows(2, prefix="GEN")
    new_count = service.upsert_scores(iter(rows))
    assert new_count == 2


# ---------------------------------------------------------------------------
# get_score
# ---------------------------------------------------------------------------


def test_get_score_found():
    from src.epss.service import EpssService
    service = EpssService()
    cve = "CVE-2024-SVC77001"
    service.upsert_scores([{
        "cve": cve,
        "score": 0.42,
        "percentile": 0.88,
        "scored_date": date.today(),
    }])
    score = service.get_score(cve)
    assert score is not None
    assert score.cve == cve
    assert score.score == pytest.approx(0.42)


def test_get_score_not_found():
    from src.epss.service import EpssService
    service = EpssService()
    assert service.get_score("CVE-9999-SVC00000") is None


def test_get_score_uppercases_input():
    """get_score should normalise lowercase CVE IDs to uppercase."""
    from src.epss.service import EpssService
    service = EpssService()
    cve = "CVE-2024-SVC77002"
    service.upsert_scores([{
        "cve": cve,
        "score": 0.5,
        "percentile": 0.9,
        "scored_date": date.today(),
    }])
    assert service.get_score(cve.lower()) is not None


# ---------------------------------------------------------------------------
# top_findings_by_epss
# ---------------------------------------------------------------------------


def test_top_findings_by_epss_empty_org():
    """No findings, no rows."""
    from src.epss.service import EpssService
    service = EpssService()
    result = service.top_findings_by_epss("epss-test-empty-org-xyz", limit=10)
    assert result == []


def test_top_findings_by_epss_orders_by_score_desc():
    """Findings whose CVE matches an EPSS row are ranked by score desc."""
    from src.db.helpers import run_db
    from src.db.models import Finding
    from src.epss.service import EpssService

    service = EpssService()
    org = "epss-test-org-rank-001"

    # Seed EPSS scores
    service.upsert_scores([
        {"cve": "CVE-2024-RNK00001", "score": 0.95, "percentile": 0.99, "scored_date": date.today()},
        {"cve": "CVE-2024-RNK00002", "score": 0.10, "percentile": 0.50, "scored_date": date.today()},
        {"cve": "CVE-2024-RNK00003", "score": 0.55, "percentile": 0.80, "scored_date": date.today()},
    ])

    # Seed matching findings
    async def _seed(session):
        from src.shared.finding_queryable_fields import extract_queryable_fields
        for i, cve in enumerate(["CVE-2024-RNK00001", "CVE-2024-RNK00002", "CVE-2024-RNK00003"]):
            detail = {"cve": cve}
            f = Finding(
                tool="deps",
                org=org,
                identity_key=f"epss-rank-{i}",
                state="open",
                severity="high",
                detail=detail,
            )
            qf = extract_queryable_fields(detail)
            f.cve_id = qf["cve_id"]
            session.add(f)
        await session.commit()

    run_db(_seed)

    result = service.top_findings_by_epss(org, limit=10)
    cves = [r["cve"] for r in result]
    # Should be ordered by score desc: 0.95, 0.55, 0.10
    assert cves == ["CVE-2024-RNK00001", "CVE-2024-RNK00003", "CVE-2024-RNK00002"]


def test_top_findings_by_epss_respects_limit():
    """The limit param caps the result count."""
    from src.db.helpers import run_db
    from src.db.models import Finding
    from src.epss.service import EpssService

    service = EpssService()
    org = "epss-test-org-limit-001"

    service.upsert_scores([
        {"cve": f"CVE-2024-LIM{10000 + i}", "score": 0.5 + i * 0.01, "percentile": 0.5, "scored_date": date.today()}
        for i in range(5)
    ])

    async def _seed(session):
        from src.shared.finding_queryable_fields import extract_queryable_fields
        for i in range(5):
            detail = {"cve": f"CVE-2024-LIM{10000 + i}"}
            f = Finding(
                tool="deps",
                org=org,
                identity_key=f"epss-limit-{i}",
                state="open",
                severity="high",
                detail=detail,
            )
            f.cve_id = extract_queryable_fields(detail)["cve_id"]
            session.add(f)
        await session.commit()

    run_db(_seed)

    result = service.top_findings_by_epss(org, limit=2)
    assert len(result) == 2


def test_top_findings_by_epss_excludes_closed():
    """Closed findings are not in the top list."""
    from src.db.helpers import run_db
    from src.db.models import Finding
    from src.epss.service import EpssService

    service = EpssService()
    org = "epss-test-org-closed-001"

    service.upsert_scores([
        {"cve": "CVE-2024-CLS00001", "score": 0.99, "percentile": 0.99, "scored_date": date.today()},
    ])

    async def _seed(session):
        from src.shared.finding_queryable_fields import extract_queryable_fields
        detail = {"cve": "CVE-2024-CLS00001"}
        f = Finding(
            tool="deps",
            org=org,
            identity_key="epss-closed",
            state="closed",
            severity="high",
            detail=detail,
        )
        f.cve_id = extract_queryable_fields(detail)["cve_id"]
        session.add(f)
        await session.commit()

    run_db(_seed)

    assert service.top_findings_by_epss(org, limit=10) == []
