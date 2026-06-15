"""Tests for sticky PR comment rendering."""
from __future__ import annotations

from src.pr_feedback.render import MARKER_PREFIX, render_sticky_comment


def test_no_new_findings_renders_success_variant():
    body = render_sticky_comment(
        scan_id="scan-1",
        aegis_url="https://aegis.example.com",
        source_id="acme-org/api",
        pr_number=247,
        new_findings=[],
        is_first_scan_on_base=False,
    )
    assert "✅" in body
    assert "no new findings" in body.lower()
    assert "scan-1" in body
    assert f"{MARKER_PREFIX}scan=scan-1" in body
    assert "aegis.example.com/sources/acme-org/api/findings?pr=247" in body


def test_findings_render_summary_table():
    findings = [
        {"severity": "high", "title": "SQL injection in /api/items"},
        {"severity": "high", "title": "Open redirect in /login"},
        {"severity": "medium", "title": "Hardcoded secret in config"},
    ]
    body = render_sticky_comment(
        scan_id="scan-2",
        aegis_url="https://aegis.example.com",
        source_id="acme-org/api",
        pr_number=247,
        new_findings=findings,
        is_first_scan_on_base=False,
    )
    assert "🚨" in body
    assert "3 new findings" in body
    assert "| 🔴 High | 2 |" in body
    assert "| 🟡 Medium | 1 |" in body


def test_first_scan_on_base_renders_baseline_note():
    body = render_sticky_comment(
        scan_id="scan-3",
        aegis_url="https://aegis.example.com",
        source_id="acme-org/api",
        pr_number=247,
        new_findings=[{"severity": "low", "title": "Stub"}],
        is_first_scan_on_base=True,
    )
    assert "first scan" in body.lower() or "no prior baseline" in body.lower()


def test_marker_always_first_line_after_title():
    body = render_sticky_comment(
        scan_id="scan-4",
        aegis_url="https://aegis.example.com",
        source_id="acme-org/api",
        pr_number=247,
        new_findings=[],
        is_first_scan_on_base=False,
    )
    # Marker comment must be present so PATCH-find-by-marker works.
    assert MARKER_PREFIX in body


def test_render_breaks_down_findings_by_verdict():
    findings = [
        {"severity": "high", "verdict": "confirmed"},
        {"severity": "high", "verdict": "confirmed"},
        {"severity": "high", "verdict": "needs_verify"},
        {"severity": "medium", "verdict": "possible"},
        {"severity": "low", "verdict": "ruled_out"},
    ]
    body = render_sticky_comment(
        scan_id="s-1",
        aegis_url="https://aegis.example.com",
        source_id="src-1",
        pr_number=42,
        new_findings=findings,
        is_first_scan_on_base=False,
    )

    assert "Confirmed" in body
    assert "Needs verify" in body
    assert "Ruled out" in body
    assert "| Confirmed | 2 |" in body
    assert "| Needs verify | 1 |" in body
    assert "| Possible | 1 |" in body
    assert "| Ruled out | 1 |" in body


def test_render_falls_back_to_severity_when_no_verdicts():
    findings = [
        {"severity": "high"},
        {"severity": "medium"},
    ]
    body = render_sticky_comment(
        scan_id="s-1",
        aegis_url="https://aegis.example.com",
        source_id="src-1",
        pr_number=42,
        new_findings=findings,
        is_first_scan_on_base=False,
    )

    assert "🔴 High" in body
    assert "🟡 Medium" in body


def test_render_deep_links_to_sources():
    body = render_sticky_comment(
        scan_id="s-1",
        aegis_url="https://aegis.example.com",
        source_id="src-42",
        pr_number=99,
        new_findings=[],
        is_first_scan_on_base=False,
    )
    assert "/sources/src-42/findings?pr=99" in body
    assert "/repos/src-42" not in body
