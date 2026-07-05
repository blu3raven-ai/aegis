"""Unit tests for the SLA breach summary GraphQL resolver."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from src.graphql.types import BreachSummary, SeverityBreachStat


def _ctx(org: str = "acme-org") -> dict:
    return {
        "user_id": "u1",
        "role": "admin",
        "orgs": [org],
        "tier": "pro",
        "request": None,
        "_cache": {},
    }


def test_sla_breach_summary_returns_zeroed_when_no_data():
    """Resolver returns all-zero stats when the service returns an empty dict."""
    from src.graphql.sla_resolvers import sla_breach_summary

    with patch("src.graphql.sla_resolvers.get_sla_service") as mock_factory:
        mock_factory.return_value.get_breach_summary.return_value = {}
        result = sla_breach_summary(org="acme-org", info_context=_ctx("acme-org"))

    assert isinstance(result, BreachSummary)
    for attr in ("critical", "high", "medium", "low"):
        stat = getattr(result, attr)
        assert isinstance(stat, SeverityBreachStat)
        assert stat.open == 0
        assert stat.breached == 0
        assert stat.breached_pct == 0.0


def test_sla_breach_summary_aggregates_single_org():
    """Resolver correctly maps service data to typed fields for a single org."""
    from src.graphql.sla_resolvers import sla_breach_summary

    service_data = {
        "critical": {"open": 10, "breached": 4, "breached_pct": 0.4},
        "high": {"open": 20, "breached": 2, "breached_pct": 0.1},
        "medium": {"open": 5, "breached": 0, "breached_pct": 0.0},
        "low": {"open": 3, "breached": 1, "breached_pct": 0.3333},
    }

    with patch("src.graphql.sla_resolvers.get_sla_service") as mock_factory:
        mock_factory.return_value.get_breach_summary.return_value = service_data
        result = sla_breach_summary(org="acme-org", info_context=_ctx("acme-org"))

    assert result.critical.open == 10
    assert result.critical.breached == 4
    assert result.critical.breached_pct == pytest.approx(0.4)
    assert result.high.open == 20
    assert result.high.breached == 2
    assert result.medium.open == 5
    assert result.medium.breached == 0
    assert result.low.open == 3
    assert result.low.breached == 1


def test_sla_breach_summary_multi_org_sums_counts():
    """Resolver sums open/breached across multiple orgs and recomputes breached_pct."""
    from src.graphql.sla_resolvers import sla_breach_summary

    org_a_data = {
        "critical": {"open": 10, "breached": 4, "breached_pct": 0.4},
        "high": {"open": 5, "breached": 1, "breached_pct": 0.2},
        "medium": {"open": 0, "breached": 0, "breached_pct": 0.0},
        "low": {"open": 2, "breached": 0, "breached_pct": 0.0},
    }
    org_b_data = {
        "critical": {"open": 6, "breached": 2, "breached_pct": 0.3333},
        "high": {"open": 4, "breached": 0, "breached_pct": 0.0},
        "medium": {"open": 0, "breached": 0, "breached_pct": 0.0},
        "low": {"open": 0, "breached": 0, "breached_pct": 0.0},
    }

    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a", "org-b"], "tier": "pro", "request": None, "_cache": {}}

    def _side_effect(org_id: str):
        return org_a_data if org_id == "org-a" else org_b_data

    with patch("src.graphql.sla_resolvers.get_sla_service") as mock_factory:
        mock_factory.return_value.get_breach_summary.side_effect = _side_effect
        result = sla_breach_summary(org="org-a,org-b", info_context=ctx)

    assert result.critical.open == 16
    assert result.critical.breached == 6
    assert result.critical.breached_pct == pytest.approx(6 / 16)
    assert result.high.open == 9
    assert result.high.breached == 1
