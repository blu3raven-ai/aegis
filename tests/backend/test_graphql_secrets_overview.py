"""Tests for secrets_overview and secrets_filter_options resolvers."""
from __future__ import annotations

from unittest.mock import patch

from src.graphql.secrets_resolvers import secrets_overview, secrets_filter_options


MOCK_FINDINGS = [
    {"secretIdentity": "si-1", "fingerprint": "fp-1", "reviewStatus": "new",
     "detector": "generic-api-key", "repository": "web-app",
     "organization": "acme-corp", "source": "github"},
    {"secretIdentity": "si-2", "fingerprint": "fp-2", "reviewStatus": "confirmed",
     "detector": "aws-access-key", "repository": "api-server",
     "organization": "acme-corp", "source": "github"},
    {"secretIdentity": "si-3", "fingerprint": "fp-3", "reviewStatus": "false_positive",
     "detector": "github-pat", "repository": "auth-service",
     "organization": "acme-corp", "source": "github"},
    {"secretIdentity": "si-1", "fingerprint": "fp-4", "reviewStatus": "new",
     "detector": "generic-api-key", "repository": "web-app",
     "organization": "acme-corp", "source": "gitlab"},
    {"secretIdentity": "si-4", "fingerprint": "fp-5", "reviewStatus": "action_taken",
     "detector": "generic-api-key", "repository": "web-app",
     "organization": "other-org", "source": "gitlab"},
]

CTX = {
    "user_id": "test",
    "role": "owner",
    "orgs": ["acme-corp"],
    "tier": "pro",
    "request": None,
    "_cache": {},
}


def _overview(**kwargs):
    defaults = dict(org="acme-corp", info_context=CTX)
    defaults.update(kwargs)
    with patch("src.graphql.secrets_resolvers._load_scoped_findings", return_value=list(MOCK_FINDINGS)):
        return secrets_overview(**defaults)


def _filter_options(**kwargs):
    defaults = dict(org="acme-corp", info_context=CTX)
    defaults.update(kwargs)
    with patch("src.graphql.secrets_resolvers._load_scoped_findings", return_value=list(MOCK_FINDINGS)):
        return secrets_filter_options(**defaults)


def test_overview_unique_key_count():
    result = _overview()
    assert result.unique_key_count == 4


def test_overview_total_findings_count():
    result = _overview()
    assert result.total_findings_count == 5


def test_overview_review_funnel():
    result = _overview()
    assert result.review_funnel.new_count == 2
    assert result.review_funnel.confirmed_count == 1
    assert result.review_funnel.false_positive_count == 1
    assert result.review_funnel.action_taken_count == 1


def test_overview_source_breakdown_sorted_desc():
    result = _overview()
    counts = [(s.source, s.count) for s in result.source_breakdown]
    assert counts[0] == ("github", 3)
    assert counts[1] == ("gitlab", 2)


def test_overview_empty_org():
    with patch("src.graphql.secrets_resolvers._load_scoped_findings", return_value=[]):
        result = secrets_overview(org="empty-org", info_context=CTX)
    assert result.unique_key_count == 0
    assert result.total_findings_count == 0
    assert result.review_funnel.new_count == 0
    assert result.source_breakdown == []


def test_filter_options_organizations():
    result = _filter_options()
    assert result.organizations == ["acme-corp", "other-org"]


def test_filter_options_repositories():
    result = _filter_options()
    assert result.repositories == ["api-server", "auth-service", "web-app"]


def test_filter_options_detectors():
    result = _filter_options()
    assert result.detectors == ["aws-access-key", "generic-api-key", "github-pat"]


def test_filter_options_sources():
    result = _filter_options()
    assert result.sources == ["github", "gitlab"]


def test_filter_options_sorted():
    result = _filter_options()
    assert result.organizations == sorted(result.organizations)
    assert result.repositories == sorted(result.repositories)
    assert result.detectors == sorted(result.detectors)
    assert result.sources == sorted(result.sources)


def test_filter_options_excludes_empty():
    findings_with_empty = [
        {"secretIdentity": "si-1", "fingerprint": "fp-1", "reviewStatus": "new",
         "detector": "", "repository": "", "organization": "", "source": ""}
    ]
    with patch("src.graphql.secrets_resolvers._load_scoped_findings", return_value=findings_with_empty):
        result = secrets_filter_options(org="acme-corp", info_context=CTX)
    assert result.organizations == []
    assert result.repositories == []
    assert result.detectors == []
    assert result.sources == []


def test_filter_options_deduplicates():
    result = _filter_options()
    assert result.detectors.count("generic-api-key") == 1
