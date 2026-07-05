"""Tests for ArgusConnector — HTTP calls, fallback on failure, auth header."""
from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from src.argus.connector import (
    ArgusConnector,
    Decision,
    Explanation,
    NullArgusConnector,
    RiskScore,
    _ArgusError,
    get_argus_connector,
)


ENDPOINT = "https://argus.example.com"
API_KEY = "test-api-key-secure"


def _connector() -> ArgusConnector:
    return ArgusConnector(endpoint=ENDPOINT, api_key=API_KEY)


def _mock_response(data: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = data
    if status >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=resp
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


# ── score_finding ─────────────────────────────────────────────────────────────


def test_score_finding_sends_metadata_fields():
    captured_body = {}

    def fake_post(url, json, headers):
        captured_body.update(json)
        return _mock_response({"score": 85.0, "rationale_id": "r-001"})

    connector = _connector()
    with patch.object(connector, "_post", side_effect=lambda path, body: (
        captured_body.update(body) or {"score": 85.0, "rationale_id": "r-001"}
    )):
        result = connector.score_finding({
            "cve_id": "CVE-2024-1234",
            "severity": "high",
            "package": "lodash",
            "version": "4.17.21",
            "epss_score": 0.4,
        })

    assert isinstance(result, RiskScore)
    assert result.source == "argus"
    assert result.score == 85.0
    assert result.rationale_id == "r-001"
    assert "cve_id" in captured_body


def test_score_finding_falls_back_on_http_error():
    # _post wraps httpx errors into _ArgusError before score_finding sees them.
    connector = _connector()

    with patch.object(connector, "_post", side_effect=_ArgusError("HTTP 503")):
        result = connector.score_finding({"severity": "high", "epss_score": 0.5})

    assert result.source == "heuristic"
    assert 0 <= result.score <= 100


def test_score_finding_falls_back_on_network_error():
    connector = _connector()

    with patch.object(connector, "_post", side_effect=_ArgusError("timeout")):
        result = connector.score_finding({"severity": "medium"})

    assert result.source == "heuristic"


def test_score_finding_safe_payload_excludes_secret_values():
    """_safe_finding_payload allowlist must not include secret content."""
    captured = {}

    connector = _connector()
    with patch.object(connector, "_post", side_effect=lambda path, body: (
        captured.update(body) or {"score": 50.0}
    )):
        connector.score_finding({
            "cve_id": "CVE-2024-9999",
            "severity": "medium",
            "secret_value": "ACTUAL_SECRET_DO_NOT_SEND",  # must be stripped
            "raw_source_code": "def main(): ...",           # must be stripped
        })

    assert "secret_value" not in captured
    assert "raw_source_code" not in captured


# ── decide_go_no_go ───────────────────────────────────────────────────────────


def test_decide_go_no_go_success():
    connector = _connector()
    resp = {"decision": "block", "blockers": ["f-1"], "rationale_id": "pol-999"}

    with patch.object(connector, "_post", return_value=resp):
        result = connector.decide_go_no_go("svc-a", [{"severity": "critical", "id": "f-1"}])

    assert isinstance(result, Decision)
    assert result.decision == "block"
    assert result.source == "argus"
    assert result.rationale_id == "pol-999"


def test_decide_go_no_go_falls_back_on_error():
    connector = _connector()

    with patch.object(connector, "_post", side_effect=_ArgusError("no argus")):
        result = connector.decide_go_no_go("svc-b", [{"id": "f-2", "severity": "high"}])

    assert result.source == "heuristic"
    assert result.decision in ("allow", "warn", "block")


# ── explain_chain ─────────────────────────────────────────────────────────────


def test_explain_chain_success():
    connector = _connector()
    resp = {
        "markdown": "## Chain\nThis chain...",
        "fix_suggestions": [{"type": "patch", "package": "lodash", "target_version": "4.17.22"}],
    }

    chain = {
        "chain_id": "ch-1",
        "chain_type": "cve_to_secret",
        "findings": [{"cve_id": "CVE-2024-0001", "severity": "high"}],
        "edges": [{"from_id": 1, "to_id": 2, "edge_type": "reaches"}],
    }

    with patch.object(connector, "_post", return_value=resp):
        result = connector.explain_chain(chain)

    assert isinstance(result, Explanation)
    assert result.source == "argus"
    assert "Chain" in result.markdown
    assert len(result.fix_suggestions) == 1


def test_explain_chain_falls_back_on_error():
    connector = _connector()

    with patch.object(connector, "_post", side_effect=_ArgusError("no argus")):
        result = connector.explain_chain({"chain_type": "test", "findings": [], "edges": []})

    assert result.source == "heuristic"
    assert len(result.markdown) > 0


def test_explain_chain_strips_code_contents():
    """_safe_chain_payload must not forward edge contents or raw code."""
    captured = {}

    connector = _connector()
    with patch.object(connector, "_post", side_effect=lambda path, body: (
        captured.update(body) or {"markdown": "", "fix_suggestions": []}
    )):
        connector.explain_chain({
            "chain_type": "test",
            "findings": [],
            "edges": [{"from_id": 1, "to_id": 2, "edge_type": "reaches", "code_diff": "SECRET"}],
        })

    if "edges" in captured:
        for edge in captured["edges"]:
            assert "code_diff" not in edge


# ── fetch_premium_rule_pack ───────────────────────────────────────────────────


def test_fetch_premium_rule_pack_success():
    connector = _connector()
    pack = {"rules": [{"id": "r-1", "name": "CVE Priority Boost"}]}

    with patch.object(connector, "_get", return_value=pack):
        result = connector.fetch_premium_rule_pack()

    assert result == pack


def test_fetch_premium_rule_pack_falls_back_on_error():
    connector = _connector()

    with patch.object(connector, "_get", side_effect=_ArgusError("no argus")):
        result = connector.fetch_premium_rule_pack(since="2026-01-01")

    assert result == {}


# ── auth header ───────────────────────────────────────────────────────────────


def test_auth_header_present_in_request():
    connector = _connector()
    captured_headers = {}

    def fake_post(url, json, headers):
        captured_headers.update(headers)
        return _mock_response({"score": 50.0})

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = lambda s: mock_client
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_resp = _mock_response({"score": 50.0})
        mock_client.post.return_value = mock_resp
        mock_client_class.return_value = mock_client

        connector.score_finding({"severity": "medium"})

        call_kwargs = mock_client.post.call_args
        sent_headers = call_kwargs.kwargs.get("headers", {}) or call_kwargs[1].get("headers", {})
        assert sent_headers.get("Authorization") == f"Bearer {API_KEY}"


# ── get_argus_connector factory ───────────────────────────────────────────────


def test_factory_returns_null_when_env_unset(monkeypatch):
    monkeypatch.delenv("ARGUS_ENDPOINT", raising=False)
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    connector = get_argus_connector()
    assert isinstance(connector, NullArgusConnector)


def test_factory_returns_real_when_env_set(monkeypatch):
    monkeypatch.setenv("ARGUS_ENDPOINT", "https://argus.example.com")
    monkeypatch.setenv("ARGUS_API_KEY", "test-key")
    connector = get_argus_connector()
    assert isinstance(connector, ArgusConnector)
    assert not isinstance(connector, NullArgusConnector)


def test_factory_returns_null_when_only_endpoint_set(monkeypatch):
    monkeypatch.setenv("ARGUS_ENDPOINT", "https://argus.example.com")
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    connector = get_argus_connector()
    assert isinstance(connector, NullArgusConnector)
