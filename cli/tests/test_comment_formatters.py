"""Tests for comment_formatters — pure formatter logic, no I/O."""

from __future__ import annotations

import pytest

from aegis_cli.comment_formatters import (
    format_github_comment,
    format_gitlab_comment,
    format_bitbucket_comment,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_CRITICAL_FINDING = {
    "state": "open",
    "_scanner": "dependencies",
    "repository": {"full_name": "example-org/payments-api"},
    "security_advisory": {
        "severity": "critical",
        "ghsa_id": "GHSA-aaaa",
        "summary": "RCE via log4j reachable from public HTTP endpoint",
        "cve_ids": ["CVE-2026-3471"],
        "patched_versions": ["2.17.2"],
    },
    "dependency": {"package": {"name": "log4j", "ecosystem": "maven"}},
    "current_version": "2.14.1",
    "location": {"path": "RequestHandler.java", "start_line": 42},
    "reachable": True,
}

_HIGH_FINDING = {
    "state": "open",
    "_scanner": "sast",
    "repository": {"full_name": "example-org/image-service"},
    "security_advisory": {
        "severity": "high",
        "summary": "SSRF in image proxy reaches AWS metadata service",
    },
    "location": {"path": "internal/proxy/fetch.go", "start_line": 84},
}

_MEDIUM_FINDING = {
    "state": "open",
    "_scanner": "secrets",
    "repository": {"full_name": "example-org/api-service"},
    "severity": "medium",
    "title": "Exposed API key in environment",
}

_LOW_FINDING = {
    "state": "open",
    "_scanner": "code_scanning",
    "repository": {"full_name": "example-org/api-service"},
    "severity": "low",
    "title": "Deprecated method usage",
}

_SAMPLE_FINDINGS = [_CRITICAL_FINDING, _HIGH_FINDING, _MEDIUM_FINDING]

_SAMPLE_CHAIN = {
    "id": "CH-04127",
    "title": "RCE-reachable",
    "max_severity": "critical",
    "findings": [{"id": "f1"}, {"id": "f2"}, {"id": "f3"}],
    "repos": ["example-org/payments-api"],
}

_ALLOW_DECISION = {"decision": "allow", "rationale": "No critical or high severity findings."}
_BLOCK_DECISION = {
    "decision": "block",
    "rationale": "2 critical/high finding(s) require remediation before deploy.",
}


def _payload(findings=None, chains=None, decision=None, total=None):
    p = {
        "findings": findings if findings is not None else _SAMPLE_FINDINGS,
        "total_findings": total if total is not None else len(findings if findings is not None else _SAMPLE_FINDINGS),
        "base_url": "https://aegis.example.org",
        "scan_id": "scan-test-001",
    }
    if chains is not None:
        p["chains"] = chains
    if decision is not None:
        p["decision"] = decision
    return p


# ---------------------------------------------------------------------------
# GitHub formatter tests
# ---------------------------------------------------------------------------

class TestFormatGithubComment:
    def test_header_present(self):
        out = format_github_comment(_payload())
        assert "## 🛡️ Aegis Security Report" in out

    def test_severity_table_counts(self):
        out = format_github_comment(_payload())
        assert "🔴 Critical" in out
        assert "| 1 |" in out
        assert "🟠 High" in out

    def test_top_findings_section_present(self):
        out = format_github_comment(_payload())
        assert "### Top findings" in out

    def test_critical_finding_in_details(self):
        out = format_github_comment(_payload())
        assert "<details>" in out
        assert "RCE via log4j" in out

    def test_location_rendered(self):
        out = format_github_comment(_payload())
        assert "RequestHandler.java:42" in out

    def test_risk_score_rendered(self):
        # critical + reachable = 100 + 10 = 110; capped display is just the raw
        out = format_github_comment(_payload())
        assert "Risk score:" in out

    def test_cve_in_summary_line(self):
        out = format_github_comment(_payload())
        assert "CVE-2026-3471" in out

    def test_chains_section_when_provided(self):
        out = format_github_comment(_payload(chains=[_SAMPLE_CHAIN]))
        assert "### Chains" in out
        assert "RCE-reachable" in out
        assert "/chains/CH-04127" in out

    def test_no_chains_section_when_absent(self):
        out = format_github_comment(_payload())
        assert "### Chains" not in out

    def test_decision_block(self):
        out = format_github_comment(_payload(decision=_BLOCK_DECISION))
        assert "### Decision:" in out
        assert "❌ Block" in out

    def test_decision_allow(self):
        out = format_github_comment(_payload(decision=_ALLOW_DECISION))
        assert "✅ Allow" in out

    def test_footer_with_total_count(self):
        out = format_github_comment(_payload(total=18))
        assert "18 findings in this PR" in out
        assert "[View full report]" in out

    def test_footer_contains_scan_id(self):
        out = format_github_comment(_payload())
        assert "scan=scan-test-001" in out

    def test_empty_findings_no_findings_message(self):
        out = format_github_comment(_payload(findings=[]))
        assert "_No findings in this scan._" in out

    def test_all_low_severity_no_collapsibles(self):
        out = format_github_comment(_payload(findings=[_LOW_FINDING]))
        # No <details> blocks — only medium/low
        assert "<details>" not in out
        assert "No critical or high severity findings." in out

    def test_medium_not_in_collapsible_block(self):
        """Medium findings appear in the table but not in the collapsible list."""
        out = format_github_comment(_payload(findings=[_MEDIUM_FINDING]))
        assert "<details>" not in out

    def test_base_url_in_footer(self):
        out = format_github_comment(_payload())
        assert "https://aegis.example.org" in out

    def test_fix_hint_for_dependency(self):
        out = format_github_comment(_payload(findings=[_CRITICAL_FINDING]))
        assert "log4j" in out


# ---------------------------------------------------------------------------
# GitLab formatter tests
# ---------------------------------------------------------------------------

class TestFormatGitlabComment:
    def test_header_present(self):
        out = format_gitlab_comment(_payload())
        assert "## 🛡️ Aegis Security Report" in out

    def test_uses_details_blocks(self):
        out = format_gitlab_comment(_payload())
        assert "<details>" in out

    def test_severity_table_present(self):
        out = format_gitlab_comment(_payload())
        assert "🔴 Critical" in out
        assert "🟠 High" in out

    def test_empty_findings(self):
        out = format_gitlab_comment(_payload(findings=[]))
        assert "_No findings in this scan._" in out

    def test_chains_section(self):
        out = format_gitlab_comment(_payload(chains=[_SAMPLE_CHAIN]))
        assert "### Chains" in out

    def test_decision_block(self):
        out = format_gitlab_comment(_payload(decision=_BLOCK_DECISION))
        assert "❌ Block" in out

    def test_footer_present(self):
        out = format_gitlab_comment(_payload())
        assert "Generated by [Aegis]" in out or "Generated by" in out

    def test_identical_to_github_for_same_input(self):
        """GitHub and GitLab use the same underlying renderer."""
        p = _payload()
        assert format_github_comment(p) == format_gitlab_comment(p)


# ---------------------------------------------------------------------------
# Bitbucket formatter tests
# ---------------------------------------------------------------------------

class TestFormatBitbucketComment:
    def test_header_present(self):
        out = format_bitbucket_comment(_payload())
        assert "## Aegis Security Report" in out

    def test_no_details_blocks(self):
        """Bitbucket does not support <details> — must not use them."""
        out = format_bitbucket_comment(_payload())
        assert "<details>" not in out
        assert "<summary>" not in out

    def test_severity_table_present(self):
        out = format_bitbucket_comment(_payload())
        assert "🔴 Critical" in out

    def test_top_findings_numbered_list(self):
        out = format_bitbucket_comment(_payload())
        assert "1. **" in out

    def test_location_in_flat_list(self):
        out = format_bitbucket_comment(_payload(findings=[_CRITICAL_FINDING]))
        assert "RequestHandler.java:42" in out

    def test_chains_section(self):
        out = format_bitbucket_comment(_payload(chains=[_SAMPLE_CHAIN]))
        assert "### Chains" in out
        assert "RCE-reachable" in out

    def test_decision_block(self):
        out = format_bitbucket_comment(_payload(decision=_BLOCK_DECISION))
        assert "❌ Block" in out

    def test_empty_findings(self):
        out = format_bitbucket_comment(_payload(findings=[]))
        assert "_No findings in this scan._" in out

    def test_all_low_no_numbered_items(self):
        out = format_bitbucket_comment(_payload(findings=[_LOW_FINDING]))
        assert "No critical or high severity findings." in out
        # No numbered items for low findings
        assert "1. **" not in out

    def test_footer_present(self):
        out = format_bitbucket_comment(_payload(total=5))
        assert "5 findings" in out
        assert "[View full report]" in out

    def test_cve_in_flat_list(self):
        out = format_bitbucket_comment(_payload(findings=[_CRITICAL_FINDING]))
        assert "CVE-2026-3471" in out
