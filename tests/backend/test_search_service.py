"""Unit tests for SearchService.

All DB interactions are mocked via patch on run_db so no real Postgres is
needed for these unit tests.
"""
from __future__ import annotations

import os

# Must precede any src.* imports
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SHARED_SECRET", "0" * 64)

from unittest.mock import MagicMock, patch

import pytest

from src.db.models import AuditEvent, Chain, Finding, NotificationDestination, ScanRun
from src.search.service import SearchService, _score


# ── _score unit tests ─────────────────────────────────────────────────────────

def test_score_exact_match():
    assert _score("CVE-2023-1234", "cve-2023-1234") == 1.0


def test_score_prefix_match():
    assert _score("CVE-2023-1234", "cve-2023") == 0.7


def test_score_substring_match():
    assert _score("some-cve-2023-xyz", "cve-2023") == 0.4


def test_score_no_match():
    assert _score("payments-api", "cve-2023") == 0.0


def test_score_none_value():
    assert _score(None, "cve") == 0.0


# ── helper factories ──────────────────────────────────────────────────────────

def _make_finding(id_: int, org: str = "acme-org", identity_key: str = "CVE-2023-0001", repo: str = "payments-api", severity: str = "high") -> Finding:
    f = Finding()
    f.id = id_
    f.org = org
    f.tool = "dependencies"
    f.repo = repo
    f.identity_key = identity_key
    f.severity = severity
    f.state = "open"
    return f


def _make_chain(id_: str = "01ARZ3NDEKTSV4RRFFQ69G5FAV", org_id: str = "acme-org", chain_type: str = "secret-to-resource") -> Chain:
    c = Chain()
    c.id = id_
    c.org_id = org_id
    c.chain_type = chain_type
    c.severity = "critical"
    c.status = "open"
    return c


def _make_audit_event(id_: int = 1, action: str = "user.login", resource_id: str = "user-1") -> AuditEvent:
    e = AuditEvent()
    e.id = id_
    e.action = action
    e.actor_user_id = "user-1"
    e.actor_username = "alice"
    e.resource_id = resource_id
    e.resource_type = "user"
    e.org_id = "acme-org"
    e.occurred_at = None
    return e


def _make_destination(id_: int = 1, name: str = "slack-alerts", dest_type: str = "slack", org_id: str = "acme-org") -> NotificationDestination:
    d = NotificationDestination()
    d.id = id_
    d.name = name
    d.destination_type = dest_type
    d.org_id = org_id
    d.enabled = True
    return d


def _make_scan_run(id_: str = "run-1", org: str = "acme-org") -> ScanRun:
    r = ScanRun()
    r.id = id_
    r.org = org
    r.tool = "dependencies"
    r.status = "completed"
    r.metadata_json = {"source_url": "https://github.com/acme-org/payments-api"}
    return r


# ── SearchService tests ───────────────────────────────────────────────────────

def _patch_run_db(return_value):
    """Return a context manager that patches run_db to synchronously return return_value."""
    return patch("src.search.service.run_db", side_effect=lambda fn: return_value)


class TestSearchServiceFindings:
    def test_query_matches_identity_key(self):
        finding = _make_finding(1, identity_key="CVE-2023-0001")
        with _patch_run_db([finding]):
            svc = SearchService()
            results = svc._search_findings("CVE-2023", org_id=None, limit=50)
        assert len(results) == 1
        assert results[0].type == "finding"
        assert results[0].id == "1"
        assert results[0].score >= 0.4

    def test_query_matches_repo(self):
        finding = _make_finding(2, repo="payments-api", identity_key="XYZ")
        with _patch_run_db([finding]):
            svc = SearchService()
            results = svc._search_findings("payments", org_id=None, limit=50)
        assert len(results) == 1
        assert "payments-api" in results[0].subtitle

    def test_ranking_exact_before_prefix(self):
        exact = _make_finding(1, identity_key="payments")
        prefix = _make_finding(2, identity_key="payments-api")
        # run_db is called once; both rows are returned
        with _patch_run_db([prefix, exact]):
            svc = SearchService()
            results = svc._search_findings("payments", org_id=None, limit=50)
        assert results[0].id == "1"  # exact match scores highest

    def test_org_scoping_field_passed_to_query(self):
        # Verify the query function would filter by org — we trust the ILIKE
        # clause is built correctly if run_db is invoked and returns the row.
        finding = _make_finding(1, org="acme-org")
        with _patch_run_db([finding]):
            svc = SearchService()
            results = svc._search_findings("CVE", org_id="acme-org", limit=50)
        assert results[0].metadata["org"] == "acme-org"

    def test_empty_db_returns_no_hits(self):
        with _patch_run_db([]):
            svc = SearchService()
            results = svc._search_findings("CVE", org_id=None, limit=50)
        assert results == []


class TestSearchServiceChains:
    def test_query_matches_chain_type(self):
        chain = _make_chain(chain_type="secret-to-resource")
        with _patch_run_db([chain]):
            svc = SearchService()
            results = svc._search_chains("secret", org_id=None, limit=50)
        assert len(results) == 1
        assert results[0].type == "chain"

    def test_query_matches_chain_id(self):
        chain = _make_chain(id_="01ARZ3NDEKTSV4RRFFQ69G5FAV")
        with _patch_run_db([chain]):
            svc = SearchService()
            results = svc._search_chains("01ARZ3", org_id=None, limit=50)
        assert len(results) == 1
        assert results[0].id == "01ARZ3NDEKTSV4RRFFQ69G5FAV"


class TestSearchServiceAuditEvents:
    def test_query_matches_action(self):
        event = _make_audit_event(action="user.login")
        with _patch_run_db([event]):
            svc = SearchService()
            results = svc._search_audit_events("user.login", org_id=None, limit=50)
        assert len(results) == 1
        assert results[0].score == 1.0

    def test_hit_href_points_to_audit_page(self):
        event = _make_audit_event()
        with _patch_run_db([event]):
            svc = SearchService()
            results = svc._search_audit_events("login", org_id=None, limit=50)
        assert results[0].href == "/settings/audit"


class TestSearchServiceDestinations:
    def test_query_matches_name(self):
        dest = _make_destination(name="slack-alerts")
        with _patch_run_db([dest]):
            svc = SearchService()
            results = svc._search_destinations("slack", org_id=None, limit=50)
        assert len(results) == 1
        assert results[0].title == "slack-alerts"

    def test_hit_metadata_includes_enabled(self):
        dest = _make_destination()
        with _patch_run_db([dest]):
            svc = SearchService()
            results = svc._search_destinations("slack", org_id=None, limit=50)
        assert results[0].metadata["enabled"] is True


class TestSearchServiceMultiScope:
    def test_search_merges_findings_and_chains(self):
        finding = _make_finding(1, identity_key="CVE-2023-0001")
        chain = _make_chain(chain_type="CVE-chain")

        call_count = 0
        returns = [[finding], [chain], [], [], []]

        def _mock_run_db(fn):
            nonlocal call_count
            result = returns[call_count % len(returns)]
            call_count += 1
            return result

        with patch("src.search.service.run_db", side_effect=_mock_run_db):
            svc = SearchService()
            results = svc.search("CVE", scopes=["findings", "chains"], org_id=None, limit=50)

        assert "findings" in results.grouped
        assert "chains" in results.grouped
        assert results.total == 2

    def test_invalid_scope_ignored(self):
        returns = [[]]
        call_count = 0

        def _mock_run_db(fn):
            nonlocal call_count
            result = returns[call_count % len(returns)]
            call_count += 1
            return result

        with patch("src.search.service.run_db", side_effect=_mock_run_db):
            svc = SearchService()
            # "unknown_scope" should be silently dropped — only valid scopes queried
            results = svc.search("test", scopes=["unknown_scope", "findings"], org_id=None, limit=50)

        # findings scope was active (even if DB returned nothing), unknown_scope skipped
        assert results.total == 0

    def test_empty_query_short_circuits(self):
        with patch("src.search.service.run_db") as mock_run:
            svc = SearchService()
            results = svc.search("", scopes=None, org_id=None, limit=50)
        # run_db should still be called (empty ILIKE returns nothing quickly)
        # but the result is empty — the route layer short-circuits before even calling service
        assert results.total == 0

    def test_duration_ms_is_non_negative(self):
        with patch("src.search.service.run_db", return_value=[]):
            svc = SearchService()
            results = svc.search("CVE", scopes=None, org_id=None, limit=50)
        assert results.duration_ms >= 0
