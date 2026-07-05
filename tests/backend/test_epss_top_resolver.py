"""Unit tests for the EPSS top findings GraphQL resolver."""
from __future__ import annotations

from unittest.mock import patch

from src.graphql.types import EpssTopFinding, EpssTopResponse


def _ctx(org: str = "acme-org") -> dict:
    return {
        "user_id": "u1",
        "role": "admin",
        "orgs": [org],
        "tier": "pro",
        "request": None,
        "_cache": {},
    }


def _finding(finding_id: int, epss_score: float, severity: str = "high") -> dict:
    return {
        "finding_id": finding_id,
        "tool": "dependencies",
        "repo": "acme-org/repo",
        "severity": severity,
        "identity_key": f"CVE-2024-{finding_id:04d}",
        "cve": f"CVE-2024-{finding_id:04d}",
        "epss_score": epss_score,
        "epss_percentile": epss_score * 100,
        "scored_date": "2024-01-01",
    }


def test_epss_top_returns_empty_when_no_findings():
    """Resolver returns an empty list when the service finds no matching findings."""
    from src.graphql.epss_resolvers import epss_top

    with patch("src.graphql.epss_resolvers._service") as mock_svc:
        mock_svc.top_findings_by_epss.return_value = []
        result = epss_top(org="acme-org", limit=20, info_context=_ctx("acme-org"))

    assert isinstance(result, EpssTopResponse)
    assert result.findings == []
    assert result.count == 0


def test_epss_top_returns_findings_sorted_by_score_desc():
    """Resolver sorts findings by EPSS score descending."""
    from src.graphql.epss_resolvers import epss_top

    raw = [
        _finding(1, 0.3),
        _finding(2, 0.9),
        _finding(3, 0.1),
        _finding(4, 0.7),
    ]

    with patch("src.graphql.epss_resolvers._service") as mock_svc:
        mock_svc.top_findings_by_epss.return_value = raw
        result = epss_top(org="acme-org", limit=20, info_context=_ctx("acme-org"))

    scores = [f.epss_score for f in result.findings]
    assert scores == sorted(scores, reverse=True)
    assert scores[0] == 0.9
    assert scores[-1] == 0.1


def test_epss_top_respects_limit():
    """Resolver trims results to the requested limit."""
    from src.graphql.epss_resolvers import epss_top

    raw = [_finding(i, float(i) / 100) for i in range(1, 51)]  # 50 findings

    with patch("src.graphql.epss_resolvers._service") as mock_svc:
        mock_svc.top_findings_by_epss.return_value = raw
        result = epss_top(org="acme-org", limit=10, info_context=_ctx("acme-org"))

    assert len(result.findings) == 10
    assert result.count == 10


def test_epss_top_finding_fields_mapped_correctly():
    """Resolver maps all fields from the service dict to the typed object."""
    from src.graphql.epss_resolvers import epss_top

    raw = [_finding(42, 0.55)]

    with patch("src.graphql.epss_resolvers._service") as mock_svc:
        mock_svc.top_findings_by_epss.return_value = raw
        result = epss_top(org="acme-org", limit=20, info_context=_ctx("acme-org"))

    assert result.count == 1
    f = result.findings[0]
    assert isinstance(f, EpssTopFinding)
    assert f.finding_id == 42
    assert f.epss_score == 0.55
    assert f.cve == "CVE-2024-0042"
    assert f.scored_date == "2024-01-01"
