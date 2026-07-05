"""Tests for the Aegis MCP server — tool handlers and resource reads.

Strategy: build the Server object and register handlers via the same code path
that run_stdio uses, then call the handler functions directly without starting
real stdio.  AegisClient is replaced with a mock to keep tests fast and
network-free.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from aegis_cli.mcp.server import _build_server, _dispatch_resource, _dispatch_tool
from aegis_cli.client import AegisAPIError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_cfg(org: str = "acme-org") -> MagicMock:
    cfg = MagicMock()
    cfg.base_url = "https://aegis.example.org"
    cfg.api_token = "test-token"
    cfg.default_org = org
    return cfg


def _make_client() -> MagicMock:
    return MagicMock()


# ---------------------------------------------------------------------------
# _build_server
# ---------------------------------------------------------------------------


def test_build_server_returns_server_client_cfg():
    with patch("aegis_cli.mcp.server.load_config") as mock_cfg, \
         patch("aegis_cli.mcp.server.AegisClient") as mock_client_cls:
        mock_cfg.return_value = _make_cfg()
        mock_client_cls.return_value = _make_client()

        server, client, cfg = _build_server()

        assert server.name == "aegis"
        assert client is mock_client_cls.return_value
        mock_client_cls.assert_called_once_with(
            base_url="https://aegis.example.org",
            api_token="test-token",
        )


# ---------------------------------------------------------------------------
# scan_current_workspace
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_current_workspace_calls_trigger_scan():
    client = _make_client()
    cfg = _make_cfg(org="acme-org")
    client.trigger_scan.return_value = {
        "runs": [{"org": "acme-org", "queued": True}],
        "message": "Started",
    }

    result = await _dispatch_tool(
        "scan_current_workspace",
        {"scanner_type": "dependencies"},
        client,
        cfg,
    )
    data = json.loads(result)

    client.trigger_scan.assert_called_once_with(
        org="acme-org",
        scanner_type="dependencies",
        repo=None,
    )
    assert data["runs"][0]["org"] == "acme-org"


@pytest.mark.asyncio
async def test_scan_current_workspace_defaults_scanner_type():
    client = _make_client()
    cfg = _make_cfg()
    client.trigger_scan.return_value = {"runs": [], "message": "ok"}

    await _dispatch_tool("scan_current_workspace", {}, client, cfg)

    client.trigger_scan.assert_called_once_with(
        org="acme-org",
        scanner_type="dependencies",
        repo=None,
    )


@pytest.mark.asyncio
async def test_scan_current_workspace_passes_repo_hint():
    client = _make_client()
    cfg = _make_cfg()
    client.trigger_scan.return_value = {"runs": [], "message": "ok"}

    await _dispatch_tool(
        "scan_current_workspace",
        {"scanner_type": "secrets", "repo": "acme-org/api-service"},
        client,
        cfg,
    )

    client.trigger_scan.assert_called_once_with(
        org="acme-org",
        scanner_type="secrets",
        repo="acme-org/api-service",
    )


# ---------------------------------------------------------------------------
# get_findings
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_findings_returns_json_array():
    client = _make_client()
    cfg = _make_cfg()
    findings = [
        {"id": "f1", "severity": "critical", "_scanner": "dependencies"},
        {"id": "f2", "severity": "high", "_scanner": "code_scanning"},
    ]
    client.get_findings.return_value = findings

    result = await _dispatch_tool("get_findings", {}, client, cfg)
    data = json.loads(result)

    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["id"] == "f1"


@pytest.mark.asyncio
async def test_get_findings_passes_filters():
    client = _make_client()
    cfg = _make_cfg()
    client.get_findings.return_value = []

    await _dispatch_tool(
        "get_findings",
        {
            "repo": "acme-org/svc",
            "severity": ["critical", "high"],
            "scanner": ["dependencies"],
        },
        client,
        cfg,
    )

    client.get_findings.assert_called_once_with(
        org="acme-org",
        repo="acme-org/svc",
        severity=["critical", "high"],
        scanner=["dependencies"],
    )


# ---------------------------------------------------------------------------
# explain_finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_explain_finding_calls_get_explanation():
    client = _make_client()
    cfg = _make_cfg()
    explanation = {
        "finding_id": "abc-123",
        "markdown": "This is a critical CVE.",
        "fix_suggestions": ["Upgrade to version 2.0"],
        "source": "argus",
    }
    client.get_explanation.return_value = explanation

    result = await _dispatch_tool(
        "explain_finding",
        {"finding_id": "abc-123"},
        client,
        cfg,
    )
    data = json.loads(result)

    client.get_explanation.assert_called_once_with(finding_id="abc-123")
    assert data["finding_id"] == "abc-123"
    assert "fix_suggestions" in data


@pytest.mark.asyncio
async def test_explain_finding_stub_response_shape():
    """Stub response (endpoint 404) must still have required keys."""
    client = _make_client()
    cfg = _make_cfg()
    client.get_explanation.return_value = {
        "finding_id": "xyz",
        "markdown": "Explanation not available.",
        "fix_suggestions": [],
        "source": "stub",
    }

    result = await _dispatch_tool(
        "explain_finding", {"finding_id": "xyz"}, client, cfg
    )
    data = json.loads(result)

    assert "markdown" in data
    assert isinstance(data["fix_suggestions"], list)


# ---------------------------------------------------------------------------
# lookup_cve
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_cve_calls_client():
    client = _make_client()
    cfg = _make_cfg()
    cve_payload = {
        "cve_id": "CVE-2024-99999",
        "cve_info": {"description": "A test CVE."},
        "epss": 0.42,
        "exploit_availability": True,
    }
    client.lookup_cve.return_value = cve_payload

    result = await _dispatch_tool(
        "lookup_cve", {"cve_id": "CVE-2024-99999"}, client, cfg
    )
    data = json.loads(result)

    client.lookup_cve.assert_called_once_with(cve_id="CVE-2024-99999")
    assert data["cve_id"] == "CVE-2024-99999"
    assert "epss" in data


@pytest.mark.asyncio
async def test_lookup_cve_stub_has_required_keys():
    client = _make_client()
    cfg = _make_cfg()
    client.lookup_cve.return_value = {
        "cve_id": "CVE-2024-00001",
        "cve_info": None,
        "epss": None,
        "exploit_availability": None,
        "source": "stub",
    }

    result = await _dispatch_tool(
        "lookup_cve", {"cve_id": "CVE-2024-00001"}, client, cfg
    )
    data = json.loads(result)

    assert data["cve_id"] == "CVE-2024-00001"
    assert "exploit_availability" in data


# ---------------------------------------------------------------------------
# check_dependency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_dependency_calls_client():
    client = _make_client()
    cfg = _make_cfg()
    client.check_dependency.return_value = {
        "package_name": "lodash",
        "version": "4.17.20",
        "vulnerable": True,
        "advisories": [{"ghsa_id": "GHSA-abc"}],
    }

    result = await _dispatch_tool(
        "check_dependency",
        {"package_name": "lodash", "version": "4.17.20"},
        client,
        cfg,
    )
    data = json.loads(result)

    client.check_dependency.assert_called_once_with(
        package_name="lodash", version="4.17.20"
    )
    assert data["vulnerable"] is True
    assert isinstance(data["advisories"], list)


@pytest.mark.asyncio
async def test_check_dependency_stub_shape():
    client = _make_client()
    cfg = _make_cfg()
    client.check_dependency.return_value = {
        "package_name": "requests",
        "version": "2.28.0",
        "vulnerable": None,
        "advisories": [],
        "source": "stub",
    }

    result = await _dispatch_tool(
        "check_dependency",
        {"package_name": "requests", "version": "2.28.0"},
        client,
        cfg,
    )
    data = json.loads(result)

    assert "vulnerable" in data
    assert isinstance(data["advisories"], list)


# ---------------------------------------------------------------------------
# get_decision
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_decision_calls_client():
    client = _make_client()
    cfg = _make_cfg(org="acme-org")
    client.get_decision.return_value = {
        "decision": "allow",
        "blockers": [],
        "rationale": "No critical findings.",
    }

    result = await _dispatch_tool(
        "get_decision",
        {"repo": "acme-org/svc", "block_on": ["critical"]},
        client,
        cfg,
    )
    data = json.loads(result)

    client.get_decision.assert_called_once_with(
        org="acme-org",
        repo="acme-org/svc",
        service_id=None,
        block_on=["critical"],
    )
    assert data["decision"] == "allow"


@pytest.mark.asyncio
async def test_get_decision_block_verdict():
    client = _make_client()
    cfg = _make_cfg()
    client.get_decision.return_value = {
        "decision": "block",
        "blockers": [{"id": "f1", "severity": "critical"}],
        "rationale": "1 critical finding.",
        "source": "local",
    }

    result = await _dispatch_tool("get_decision", {}, client, cfg)
    data = json.loads(result)

    assert data["decision"] == "block"
    assert len(data["blockers"]) == 1


@pytest.mark.asyncio
async def test_get_decision_falls_back_to_org_as_repo():
    """When repo is not provided, org is used as the repo argument."""
    client = _make_client()
    cfg = _make_cfg(org="acme-org")
    client.get_decision.return_value = {"decision": "allow", "blockers": [], "rationale": ""}

    await _dispatch_tool("get_decision", {}, client, cfg)

    call_kwargs = client.get_decision.call_args.kwargs
    assert call_kwargs["repo"] == "acme-org"


# ---------------------------------------------------------------------------
# Unknown tool
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_tool_raises_value_error():
    client = _make_client()
    cfg = _make_cfg()
    with pytest.raises(ValueError, match="Unknown tool"):
        await _dispatch_tool("nonexistent_tool", {}, client, cfg)


# ---------------------------------------------------------------------------
# Resource reads
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resource_findings_calls_get_findings():
    client = _make_client()
    cfg = _make_cfg(org="acme-org")
    client.get_findings.return_value = [{"id": "f1"}]

    result = await _dispatch_resource(
        "aegis://findings/acme-org/api-service", client, cfg
    )
    data = json.loads(result)

    client.get_findings.assert_called_once_with(
        org="acme-org",
        repo="acme-org/api-service",
    )
    assert data[0]["id"] == "f1"


@pytest.mark.asyncio
async def test_resource_sbom_calls_get_sbom():
    client = _make_client()
    cfg = _make_cfg(org="acme-org")
    client.get_sbom.return_value = {"packages": []}

    result = await _dispatch_resource(
        "aegis://sbom/acme-org/api-service", client, cfg
    )
    data = json.loads(result)

    client.get_sbom.assert_called_once_with(org="acme-org", repo="acme-org/api-service")
    assert "packages" in data


@pytest.mark.asyncio
async def test_resource_chain_calls_get_chain():
    client = _make_client()
    cfg = _make_cfg(org="acme-org")
    client.get_chain.return_value = {"id": "chain-xyz", "nodes": []}

    result = await _dispatch_resource("aegis://chains/chain-xyz", client, cfg)
    data = json.loads(result)

    client.get_chain.assert_called_once_with(org="acme-org", chain_id="chain-xyz")
    assert data["id"] == "chain-xyz"


@pytest.mark.asyncio
async def test_resource_unknown_uri_raises_value_error():
    client = _make_client()
    cfg = _make_cfg()
    with pytest.raises(ValueError, match="Unknown resource URI"):
        await _dispatch_resource("aegis://unknown/path", client, cfg)
