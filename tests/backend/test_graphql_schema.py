import pytest
from unittest.mock import patch


def test_dependencies_counts_resolver():
    from src.graphql.dependencies_resolvers import dependencies_counts
    from src.graphql.types import SeverityCounts

    mock_counts = {"total": 4, "critical": 1, "high": 2, "medium": 1, "low": 0}
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "tier": "pro", "request": None, "_cache": {}}

    with patch("src.graphql.dependencies_resolvers.get_severity_counts", return_value=mock_counts):
        result = dependencies_counts(org="org-a", info_context=ctx)

    assert isinstance(result, SeverityCounts)
    assert result.total == 4
    assert result.critical == 1
    assert result.high == 2
    assert result.medium == 1
    assert result.low == 0


def test_dependencies_findings_pagination():
    from src.graphql.dependencies_resolvers import dependencies_findings

    mock_findings = [
        {"state": "open", "security_advisory": {"severity": "high"}, "security_vulnerability": {"package": {"name": f"pkg-{i}"}}, "repository": {"full_name": f"org/repo-{i}"}}
        for i in range(50)
    ]

    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "tier": "pro", "request": None, "_cache": {}}

    with patch("src.graphql.dependencies_resolvers.read_dependencies_findings", return_value=mock_findings):
        result = dependencies_findings(org="org-a", page=1, per_page=10, info_context=ctx)

    assert result.total_count == 50
    assert len(result.items) == 10
    assert result.page_info.has_next_page is True
    assert result.page_info.total_pages == 5


def test_dependencies_findings_page_clamped():
    from src.graphql.dependencies_resolvers import dependencies_findings

    mock_findings = [{"state": "open", "security_advisory": {"severity": "high"}} for _ in range(5)]
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "tier": "pro", "request": None, "_cache": {}}

    with patch("src.graphql.dependencies_resolvers.read_dependencies_findings", return_value=mock_findings):
        result = dependencies_findings(org="org-a", page=0, per_page=25, info_context=ctx)
        assert result.page_info.has_previous_page is False
        assert len(result.items) == 5

        result2 = dependencies_findings(org="org-a", page=-3, per_page=25, info_context=ctx)
        assert len(result2.items) == 5


def test_dependencies_per_request_cache():
    """Verify get_severity_counts is called on each invocation (no in-resolver cache)."""
    from src.graphql.dependencies_resolvers import dependencies_counts

    mock_counts = {"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0}
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "_cache": {}}

    with patch("src.graphql.dependencies_resolvers.get_severity_counts", return_value=mock_counts) as mock_fn:
        dependencies_counts(org="org-a", info_context=ctx)
        dependencies_counts(org="org-a", info_context=ctx)
        assert mock_fn.call_count == 2


# ---------------------------------------------------------------------------
# Code scanning resolver tests
# ---------------------------------------------------------------------------

def test_code_scanning_counts_resolver():
    from src.graphql.code_scanning_resolvers import code_scanning_counts

    mock_counts = {"total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0}
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "tier": "pro", "request": None, "_cache": {}}
    with patch("src.graphql.code_scanning_resolvers.get_severity_counts", return_value=mock_counts):
        result = code_scanning_counts(org="org-a", info_context=ctx)
    assert result.total == 2
    assert result.critical == 1
    assert result.high == 1
    assert result.medium == 0
    assert result.low == 0


def test_code_scanning_findings_pagination():
    from src.graphql.code_scanning_resolvers import code_scanning_findings
    mock_findings = [
        {"state": "open", "severity": "high", "rule_id": f"rule-{i}", "repo_full_name": f"org/repo-{i}"}
        for i in range(30)
    ]
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "tier": "pro", "request": None, "_cache": {}}
    with patch("src.graphql.code_scanning_resolvers.read_code_scanning_findings", return_value=mock_findings):
        result = code_scanning_findings(org="org-a", page=1, per_page=10, info_context=ctx)
    assert result.total_count == 30
    assert len(result.items) == 10
    assert result.page_info.has_next_page is True
    assert result.page_info.total_pages == 3


def test_code_scanning_findings_severity_filter():
    from src.graphql.code_scanning_resolvers import code_scanning_findings
    mock_findings = [
        {"state": "open", "severity": "high"},
        {"state": "open", "severity": "critical"},
        {"state": "open", "severity": "high"},
    ]
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "tier": "pro", "request": None, "_cache": {}}
    with patch("src.graphql.code_scanning_resolvers.read_code_scanning_findings", return_value=mock_findings):
        result = code_scanning_findings(org="org-a", severity="high", info_context=ctx)
    assert result.total_count == 2


def test_code_scanning_per_request_cache():
    from src.graphql.code_scanning_resolvers import code_scanning_counts

    mock_counts = {"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0}
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "_cache": {}}
    with patch("src.graphql.code_scanning_resolvers.get_severity_counts", return_value=mock_counts) as mock_fn:
        code_scanning_counts(org="org-a", info_context=ctx)
        code_scanning_counts(org="org-a", info_context=ctx)
        assert mock_fn.call_count == 2


# ---------------------------------------------------------------------------
# Container resolver tests
# ---------------------------------------------------------------------------

def test_container_counts_resolver():
    from src.graphql.containers_resolvers import container_counts

    mock_counts = {"total": 2, "critical": 1, "high": 0, "medium": 1, "low": 0}
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "tier": "pro", "request": None, "_cache": {}}
    with patch("src.graphql.containers_resolvers.get_severity_counts", return_value=mock_counts):
        result = container_counts(org="org-a", info_context=ctx)
    assert result.total == 2
    assert result.critical == 1
    assert result.medium == 1
    assert result.high == 0


def test_container_findings_pagination():
    from src.graphql.containers_resolvers import container_findings
    mock_findings = [
        {
            "state": "open",
            "security_advisory": {"severity": "high"},
            "security_vulnerability": {"package": {"name": f"pkg-{i}"}},
            "repository": {"full_name": f"org/repo-{i}"},
        }
        for i in range(20)
    ]
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "tier": "pro", "request": None, "_cache": {}}
    with patch("src.graphql.containers_resolvers.read_container_scanning_findings", return_value=mock_findings):
        result = container_findings(org="org-a", page=2, per_page=5, info_context=ctx)
    assert result.total_count == 20
    assert len(result.items) == 5
    assert result.page_info.has_previous_page is True
    assert result.page_info.total_pages == 4


def test_container_per_request_cache():
    from src.graphql.containers_resolvers import container_counts

    mock_counts = {"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0}
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "_cache": {}}
    with patch("src.graphql.containers_resolvers.get_severity_counts", return_value=mock_counts) as mock_fn:
        container_counts(org="org-a", info_context=ctx)
        container_counts(org="org-a", info_context=ctx)
        assert mock_fn.call_count == 2


# ---------------------------------------------------------------------------
# Secrets resolver tests
# ---------------------------------------------------------------------------

def test_secret_counts_resolver():
    from src.graphql.secrets_resolvers import secret_counts

    mock_counts = {"total": 3, "critical": 1, "high": 2, "medium": 0, "low": 0}
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "tier": "pro", "request": None, "_cache": {}}
    with patch("src.graphql.secrets_resolvers.get_severity_counts", return_value=mock_counts):
        result = secret_counts(org="org-a", info_context=ctx)
    assert result.total == 3
    assert result.critical == 1
    assert result.high == 2
    assert result.medium == 0
    assert result.low == 0


def test_secret_findings_state_filter():
    from src.graphql.secrets_resolvers import secret_findings
    mock_findings = [
        {"state": "open", "reviewStatus": "new", "secretIdentity": "s1"},
        {"state": "open", "reviewStatus": "confirmed", "secretIdentity": "s2"},
        {"state": "dismissed", "reviewStatus": "false_positive", "secretIdentity": "s3"},
    ]
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "tier": "pro", "request": None, "_cache": {}}
    with patch("src.graphql.secrets_resolvers.read_latest_findings", return_value=mock_findings):
        result = secret_findings(org="org-a", state="open", info_context=ctx)
    assert result.total_count == 2
    assert all(item.review_status in ("new", "confirmed") for item in result.items)


def test_secret_findings_dismissed_filter():
    from src.graphql.secrets_resolvers import secret_findings
    mock_findings = [
        {"state": "open", "reviewStatus": "new", "secretIdentity": "s1"},
        {"state": "dismissed", "reviewStatus": "false_positive", "secretIdentity": "s2"},
    ]
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "tier": "pro", "request": None, "_cache": {}}
    with patch("src.graphql.secrets_resolvers.read_latest_findings", return_value=mock_findings):
        result = secret_findings(org="org-a", state="dismissed", info_context=ctx)
    assert result.total_count == 1
    assert result.items[0].review_status == "false_positive"


def test_secret_per_request_cache():
    from src.graphql.secrets_resolvers import secret_counts

    mock_counts = {"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0}
    ctx = {"user_id": "u1", "role": "admin", "orgs": ["org-a"], "_cache": {}}
    with patch("src.graphql.secrets_resolvers.get_severity_counts", return_value=mock_counts) as mock_fn:
        secret_counts(org="org-a", info_context=ctx)
        secret_counts(org="org-a", info_context=ctx)
        assert mock_fn.call_count == 2
