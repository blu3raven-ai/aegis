"""Tests for NullArgusConnector — always returns heuristic results without network calls."""
from __future__ import annotations

from unittest.mock import patch


from src.argus.connector import Explanation, NullArgusConnector, RiskScore


# ── score_finding ─────────────────────────────────────────────────────────────


def test_null_score_finding_returns_risk_score():
    connector = NullArgusConnector()
    result = connector.score_finding({"cve_id": "CVE-2024-0001", "severity": "high", "epss_score": 0.3})
    assert isinstance(result, RiskScore)
    assert result.source == "heuristic"
    assert 0 <= result.score <= 100
    assert result.rationale_id is None


def test_null_score_finding_no_network_calls():
    connector = NullArgusConnector()
    with patch("httpx.Client") as mock_client:
        connector.score_finding({"severity": "medium"})
    mock_client.assert_not_called()


def test_null_score_finding_critical_higher_than_low():
    connector = NullArgusConnector()
    high_score = connector.score_finding({"severity": "critical"}).score
    low_score = connector.score_finding({"severity": "low"}).score
    assert high_score > low_score


def test_null_score_finding_reachable_bonus():
    connector = NullArgusConnector()
    base = connector.score_finding({"severity": "medium"}).score
    boosted = connector.score_finding({"severity": "medium", "reachable": True}).score
    assert boosted > base


def test_null_score_finding_chain_bonus():
    connector = NullArgusConnector()
    base = connector.score_finding({"severity": "medium"}).score
    boosted = connector.score_finding({"severity": "medium", "in_chain": True}).score
    assert boosted > base


# ── explain_chain ─────────────────────────────────────────────────────────────


def test_null_explain_chain_returns_explanation():
    connector = NullArgusConnector()
    chain = {"chain_type": "cve_to_secret", "findings": [{"id": 1}], "edges": []}
    result = connector.explain_chain(chain)
    assert isinstance(result, Explanation)
    assert result.source == "heuristic"
    assert len(result.markdown) > 0
    assert result.fix_suggestions == []


def test_null_explain_chain_no_network_calls():
    connector = NullArgusConnector()
    with patch("httpx.Client") as mock_client:
        connector.explain_chain({})
    mock_client.assert_not_called()


# ── fetch_premium_rule_pack ───────────────────────────────────────────────────


def test_null_fetch_premium_rule_pack_returns_empty():
    connector = NullArgusConnector()
    result = connector.fetch_premium_rule_pack()
    assert result == {}


def test_null_fetch_premium_rule_pack_no_network_calls():
    connector = NullArgusConnector()
    with patch("httpx.Client") as mock_client:
        connector.fetch_premium_rule_pack(since="2026-01-01")
    mock_client.assert_not_called()


# ── init safety ───────────────────────────────────────────────────────────────


def test_null_connector_instantiates_without_args():
    # Must not raise even though base class requires endpoint/api_key
    connector = NullArgusConnector()
    assert connector is not None
