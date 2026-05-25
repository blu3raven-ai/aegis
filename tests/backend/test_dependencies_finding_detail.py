"""Tests for read_dependency_finding_detail_by_key and dependencies_finding_detail resolver."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def _make_finding(identity_key: str = "repo::pkg::npm::GHSA-1234::package.json"):
    f = MagicMock()
    f.tool = "dependencies"
    f.org = "acme-org"
    f.identity_key = identity_key
    f.severity = "high"
    f.state = "open"
    f.detail = {
        "packageName": "lodash",
        "ecosystem": "npm",
        "advisoryId": "GHSA-1234",
        "cveId": "CVE-2021-23337",
        "summary": "Prototype pollution",
        "description": "Full markdown description here.",
        "cvssScore": 7.2,
        "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "publishedAt": "2021-03-05T00:00:00Z",
        "advisoryUpdatedAt": "2021-04-01T00:00:00Z",
        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}],
        "manifestPath": "package.json",
        "patchedVersion": "4.17.21",
        "vulnerableVersionRange": "< 4.17.21",
        "currentVersion": "4.17.4",
        "manifestSnippet": "lodash: 4.17.4",
        "manifestMatchLine": 3,
        "source": "git",
        "scanner": "grype",
        "matchedBy": [],
        "advisoryUrl": "https://github.com/advisories/GHSA-1234",
    }
    f.repo = "acme-org/my-repo"
    f.first_seen_at = None
    f.fixed_at = None
    f.created_at = None
    f.updated_at = None
    return f


@pytest.mark.asyncio
async def test_read_dependency_finding_detail_by_key_found():
    from src.shared.finding_queries import read_dependency_finding_detail_by_key

    finding = _make_finding()
    decision = None

    mock_result = MagicMock()
    mock_result.first.return_value = (finding, decision)

    session = AsyncMock()
    session.execute = AsyncMock(return_value=mock_result)

    row = await read_dependency_finding_detail_by_key(session, "acme-org", "repo::pkg::npm::GHSA-1234::package.json")
    assert row is not None
    f, d = row
    assert f.identity_key == "repo::pkg::npm::GHSA-1234::package.json"
    assert d is None


@pytest.mark.asyncio
async def test_read_dependency_finding_detail_by_key_not_found():
    from src.shared.finding_queries import read_dependency_finding_detail_by_key

    mock_result = MagicMock()
    mock_result.first.return_value = None

    session = AsyncMock()
    session.execute = AsyncMock(return_value=mock_result)

    row = await read_dependency_finding_detail_by_key(session, "acme-org", "nonexistent::key")
    assert row is None


def test_dependencies_finding_detail_not_found():
    """Resolver returns None when the finding does not exist."""
    from src.graphql.dependencies_resolvers import dependencies_finding_detail

    ctx = {"orgs": ["acme-org"], "user_id": "u1", "request": MagicMock()}

    with patch("src.db.helpers.run_db", return_value=None):
        result = dependencies_finding_detail(org="acme-org", identity_key="missing::key", info_context=ctx)

    assert result is None


def test_dependencies_finding_detail_maps_fields():
    """Resolver maps all detail fields from the DB row."""
    from src.graphql.dependencies_resolvers import dependencies_finding_detail

    finding = _make_finding()
    decision = None
    ctx = {"orgs": ["acme-org"], "user_id": "u1", "request": MagicMock()}

    with patch("src.db.helpers.run_db", return_value=(finding, decision)):
        result = dependencies_finding_detail(org="acme-org", identity_key=finding.identity_key, info_context=ctx)

    assert result is not None
    assert result.ghsa_id == "GHSA-1234"
    assert result.cve_id == "CVE-2021-23337"
    assert result.advisory_description == "Full markdown description here."
    assert result.manifest_snippet == "lodash: 4.17.4"
    assert result.manifest_match_line == 3
    assert result.references == ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"]
    assert result.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
    assert result.published_at == "2021-03-05T00:00:00Z"


def test_dependencies_finding_detail_unauthorized():
    """Resolver raises when org is not in user's allowed orgs."""
    from src.graphql.dependencies_resolvers import dependencies_finding_detail
    from src.graphql.auth import GraphQLAuthError

    ctx = {"orgs": ["other-org"], "user_id": "u1", "request": MagicMock()}

    with pytest.raises(GraphQLAuthError):
        dependencies_finding_detail(org="acme-org", identity_key="any::key", info_context=ctx)
