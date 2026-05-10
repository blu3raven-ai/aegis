"""Tests for Secrets findings resolver filter parameters."""
from __future__ import annotations

from unittest.mock import patch

from src.graphql.secrets_resolvers import secret_findings


def _make_finding(
    identity="si-1", fingerprint="fp-1", review_status="new",
    detector="generic-api-key", repository="web-app",
    organization="acme-corp", source="github",
    file_path="config.py", snippet="AKIAIOSFODNN7EXAMPLE",
    detected_at="2026-04-01T00:00:00Z",
    classification_history=None,
):
    return {
        "secretIdentity": identity,
        "fingerprint": fingerprint,
        "reviewStatus": review_status,
        "detector": detector,
        "repository": repository,
        "organization": organization,
        "source": source,
        "filePath": file_path,
        "secretSnippet": snippet,
        "detectedAt": detected_at,
        "first_seen_at": detected_at,
        "state": "open",
        "line": 42,
        "commit": "abc1234",
        "classificationHistory": classification_history or [],
        "riskScore": 5.0,
        "occurrenceCount": 1,
    }


MOCK_FINDINGS = [
    _make_finding(identity="si-1", fingerprint="fp-1", review_status="new",
                  detector="generic-api-key", repository="web-app",
                  organization="acme-corp", source="github",
                  detected_at="2026-04-01T00:00:00Z"),
    _make_finding(identity="si-2", fingerprint="fp-2", review_status="confirmed",
                  detector="aws-access-key", repository="api-server",
                  organization="acme-corp", source="github",
                  detected_at="2026-03-15T00:00:00Z"),
    _make_finding(identity="si-3", fingerprint="fp-3", review_status="false_positive",
                  detector="github-pat", repository="auth-service",
                  organization="acme-corp", source="github",
                  file_path="deploy.sh", snippet="ghp_example123",
                  detected_at="2026-02-01T00:00:00Z",
                  classification_history=[
                      {"value": "likely_real", "source": "scanner"},
                      {"value": "false_positive", "source": "ai"},
                  ]),
    _make_finding(identity="si-4", fingerprint="fp-4", review_status="action_taken",
                  detector="generic-api-key", repository="web-app",
                  organization="other-org", source="gitlab",
                  detected_at="2025-06-01T00:00:00Z"),
]

CTX = {
    "user_id": "test",
    "role": "owner",
    "orgs": ["acme-corp"],
    "tier": "pro",
    "request": None,
    "_cache": {},
}


def _call(**kwargs):
    defaults = dict(org="acme-corp", page=1, per_page=25, info_context=CTX)
    defaults.update(kwargs)
    with patch("src.graphql.secrets_resolvers._load_scoped_findings", return_value=list(MOCK_FINDINGS)):
        return secret_findings(**defaults)


def test_review_status_new():
    result = _call(review_status="new")
    assert result.total_count == 1
    assert all(i.review_status == "new" for i in result.items)


def test_review_status_confirmed():
    result = _call(review_status="confirmed")
    assert result.total_count == 1
    assert result.items[0].id == "si-2"


def test_review_status_none_returns_all():
    result = _call(review_status=None)
    assert result.total_count == 4


def test_detector_filter():
    result = _call(detector="generic-api-key")
    assert result.total_count == 2
    assert all(i.detector == "generic-api-key" for i in result.items)


def test_detector_no_match():
    result = _call(detector="nonexistent")
    assert result.total_count == 0


def test_repository_filter():
    result = _call(repository="web-app")
    assert result.total_count == 2
    assert all(i.repository == "web-app" for i in result.items)


def test_repository_no_match():
    result = _call(repository="unknown-repo")
    assert result.total_count == 0


def test_organization_filter():
    result = _call(organization="acme-corp")
    assert result.total_count == 3


def test_organization_other():
    result = _call(organization="other-org")
    assert result.total_count == 1
    assert result.items[0].organization == "other-org"


def test_source_filter():
    result = _call(source="gitlab")
    assert result.total_count == 1
    assert result.items[0].source == "gitlab"


def test_source_none_returns_all():
    result = _call(source=None)
    assert result.total_count == 4


def test_search_by_detector():
    result = _call(search="aws-access")
    assert result.total_count == 1
    assert result.items[0].detector == "aws-access-key"


def test_search_by_repository():
    result = _call(search="auth-service")
    assert result.total_count == 1


def test_search_by_file_path():
    result = _call(search="deploy.sh")
    assert result.total_count == 1
    assert result.items[0].file_path == "deploy.sh"


def test_search_by_snippet():
    result = _call(search="ghp_example")
    assert result.total_count == 1


def test_search_case_insensitive():
    result = _call(search="GENERIC-API")
    assert result.total_count == 2


def test_search_no_match():
    result = _call(search="zzz_notfound")
    assert result.total_count == 0


def test_search_capped_at_200_chars():
    long_search = "a" * 300
    result = _call(search=long_search)
    assert result.total_count == 0


def test_classification_filter():
    result = _call(classification="likely_real")
    assert result.total_count == 1
    assert result.items[0].id == "si-3"


def test_classification_no_match():
    result = _call(classification="verified_secret")
    assert result.total_count == 0


def test_age_bucket_recent():
    result = _call(age_bucket="6mo+")
    assert result.total_count >= 1
    ids = [i.id for i in result.items]
    assert "si-4" in ids


def test_new_since_last_scan():
    result = _call(new_since_last_scan=True, last_scan_date="2026-03-01T00:00:00Z")
    assert result.total_count == 2


def test_new_since_last_scan_false_no_filter():
    result = _call(new_since_last_scan=False, last_scan_date="2026-03-01T00:00:00Z")
    assert result.total_count == 4


def test_new_since_last_scan_without_date_no_filter():
    result = _call(new_since_last_scan=True, last_scan_date=None)
    assert result.total_count == 4


def test_combined_review_status_and_detector():
    result = _call(review_status="new", detector="generic-api-key")
    assert result.total_count == 1
    assert result.items[0].id == "si-1"


def test_combined_organization_and_source():
    result = _call(organization="acme-corp", source="github")
    assert result.total_count == 3


def test_combined_all_filters_empty():
    result = _call(review_status="new", detector="aws-access-key")
    assert result.total_count == 0
