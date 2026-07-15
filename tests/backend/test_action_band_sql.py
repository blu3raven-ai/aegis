"""Parity test: _band_ordinal_sql() (Postgres CASE) must agree with the pure
band_ordinal(action_band(...)) helper for every signal combination.

The SQL CASE in findings.service and the Python helper in findings.action_band
are two encodings of the same rule; this asserts they never drift.
"""
from __future__ import annotations

from datetime import date
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from src.db.models import Finding, KevEntry
from src.findings.action_band import action_band, band_ordinal
from src.findings.service import _band_ordinal_sql


# (severity, kev_listed, reachability, distinct_cve) — covers the band-rule matrix.
# distinct_cve seeds a real cve_id that is absent from KEV, exercising the is_kev
# subquery's negative branch (distinct from the cve_id=None rows).
_CASES = [
    ("critical", True, None, False),        # KEV + high -> act (3)
    ("low", True, None, False),             # KEV, low sev -> attend (2)
    ("high", False, "reachable", False),    # reachable + high, no KEV -> attend (2)
    ("medium", False, "reachable", False),  # reachable but NOT high -> track (1): guards the is_high requirement
    ("high", False, "no_path", False),      # no_path + high -> track (1)
    ("high", False, None, True),            # real CVE absent from KEV -> track (1): is_kev negative path
    (None, True, None, False),              # unknown sev + KEV -> attend (2), never track
]


@pytest_asyncio.fixture
async def band_fixture(db_session):
    """Seed one KEV entry and a finding per matrix case. Clean up at teardown."""
    cve_kev = f"CVE-1999-{uuid4().hex[:4].upper()}"
    kev = KevEntry(cve_id=cve_kev, date_added=date(2026, 1, 1))

    findings: list[Finding] = []
    for severity, kev_listed, reachability, distinct_cve in _CASES:
        detail = {"reachability": reachability} if reachability else {}
        if kev_listed:
            cve_id = cve_kev
        elif distinct_cve:
            cve_id = f"CVE-2024-{uuid4().hex[:4].upper()}"
        else:
            cve_id = None
        findings.append(
            Finding(
                tool="dependencies_scanning",
                identity_key=f"band-{uuid4()}",
                state="open",
                severity=severity,
                cve_id=cve_id,
                detail=detail,
            )
        )
    db_session.add_all([kev, *findings])
    await db_session.commit()
    yield list(zip(_CASES, findings))
    await db_session.execute(
        delete(Finding).where(Finding.id.in_([f.id for f in findings]))
    )
    await db_session.execute(delete(KevEntry).where(KevEntry.cve_id == cve_kev))
    await db_session.commit()


@pytest.mark.asyncio
async def test_sql_band_ordinal_matches_python(db_session, band_fixture):
    band_expr = _band_ordinal_sql()
    for (severity, kev_listed, reachability, _distinct_cve), finding in band_fixture:
        sql_ordinal = (
            await db_session.execute(
                select(band_expr).where(Finding.id == finding.id)
            )
        ).scalar_one()
        py_ordinal = band_ordinal(
            action_band(severity, kev_listed=kev_listed, reachability=reachability)
        )
        assert sql_ordinal == py_ordinal, (
            f"mismatch for severity={severity!r} kev={kev_listed} "
            f"reachability={reachability!r}: sql={sql_ordinal} python={py_ordinal}"
        )


@pytest.mark.asyncio
async def test_sql_band_ordinal_expected_values(db_session, band_fixture):
    """Pin the expected ordinals so a parity bug can't pass by both sides drifting."""
    expected = {
        ("critical", True, None, False): 3,
        ("low", True, None, False): 2,
        ("high", False, "reachable", False): 2,
        ("medium", False, "reachable", False): 1,
        ("high", False, "no_path", False): 1,
        ("high", False, None, True): 1,
        (None, True, None, False): 2,
    }
    band_expr = _band_ordinal_sql()
    for case_key, finding in band_fixture:
        sql_ordinal = (
            await db_session.execute(
                select(band_expr).where(Finding.id == finding.id)
            )
        ).scalar_one()
        assert sql_ordinal == expected[case_key]
