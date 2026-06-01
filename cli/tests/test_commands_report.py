"""Tests for aegis report command and report_formatters."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aegis_cli.main import cli
from aegis_cli.report_formatters import format_html, format_json, format_markdown


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_cfg(org: str = "example-org", token: str = "testtoken") -> MagicMock:
    cfg = MagicMock()
    cfg.base_url = "https://aegis.example.org"
    cfg.api_token = token
    cfg.default_org = org
    return cfg


def _make_client(findings=None, chain=None) -> MagicMock:
    """Build a mock AegisClient with iter_all_findings returning *findings*."""
    inst = MagicMock()
    inst.__enter__ = lambda s: inst
    inst.__exit__ = MagicMock(return_value=False)
    inst.iter_all_findings.return_value = findings if findings is not None else []
    inst.get_chain.return_value = chain or {}
    return inst


_SAMPLE_FINDINGS = [
    {
        "id": "1",
        "scanner": "deps",
        "severity": "critical",
        "state": "open",
        "title": "RCE via log4j vulnerability",
        "cve": "CVE-2021-44228",
        "package": "log4j@2.14.1",
        "repo": "example-org/payments-api",
        "created_at": "2026-05-20T10:00:00+00:00",
    },
    {
        "id": "2",
        "scanner": "sast",
        "severity": "high",
        "state": "open",
        "title": "SQL injection risk",
        "repo": "example-org/image-service",
        "created_at": "2026-05-25T08:00:00+00:00",
    },
    {
        "id": "3",
        "scanner": "secrets",
        "severity": "medium",
        "state": "open",
        "title": "Exposed API key",
        "repo": "example-org/payments-api",
    },
]

_SAMPLE_CHAIN = {
    "id": "CH-test",
    "title": "RCE-reachable in payments-api",
    "max_severity": "critical",
    "findings": [{"id": "f1"}, {"id": "f2"}, {"id": "f3"}],
    "steps": [
        {"description": "Public ingress → payments-api"},
        {"description": "Untrusted input → logger.info()"},
        {"description": "log4j@2.14.1 → JNDI RCE"},
    ],
}


# ---------------------------------------------------------------------------
# format_markdown tests
# ---------------------------------------------------------------------------

class TestFormatMarkdown:
    def test_contains_report_header(self) -> None:
        body = {"org": "example-org", "findings": [], "since": "7d"}
        md = format_markdown(body)
        assert "# Aegis Security Report" in md

    def test_summary_counts(self) -> None:
        body = {"org": "example-org", "findings": _SAMPLE_FINDINGS, "since": "7d"}
        md = format_markdown(body)
        assert "Total findings: 3" in md
        assert "Critical: 1" in md
        assert "High: 1" in md
        assert "Medium: 1" in md

    def test_table_rendered(self) -> None:
        body = {"org": "example-org", "findings": _SAMPLE_FINDINGS, "since": "7d"}
        md = format_markdown(body)
        # Header row must be present
        assert "| # | Severity |" in md
        # At least one data row
        assert "| 1 |" in md

    def test_finding_title_in_table(self) -> None:
        body = {"org": "example-org", "findings": _SAMPLE_FINDINGS, "since": "7d"}
        md = format_markdown(body)
        assert "RCE via log4j" in md

    def test_chain_section_rendered(self) -> None:
        body = {
            "org": "example-org",
            "findings": [],
            "chains": [_SAMPLE_CHAIN],
            "since": "7d",
        }
        md = format_markdown(body)
        assert "## Active Chains" in md
        assert "RCE-reachable in payments-api" in md
        assert "3 findings" in md
        assert "Public ingress" in md

    def test_findings_by_repo_section(self) -> None:
        body = {"org": "example-org", "findings": _SAMPLE_FINDINGS, "since": "7d"}
        md = format_markdown(body)
        assert "## Findings by Repo" in md
        assert "payments-api" in md
        assert "image-service" in md

    def test_findings_by_scanner_section(self) -> None:
        body = {"org": "example-org", "findings": _SAMPLE_FINDINGS, "since": "7d"}
        md = format_markdown(body)
        assert "## Findings by Scanner" in md
        assert "deps" in md
        assert "secrets" in md

    def test_scope_org(self) -> None:
        body = {"org": "example-org", "findings": [], "since": "7d"}
        md = format_markdown(body)
        assert "org=example-org" in md

    def test_scope_repo(self) -> None:
        body = {"repo": "example-org/payments-api", "findings": [], "since": "7d"}
        md = format_markdown(body)
        assert "repo=example-org/payments-api" in md

    def test_scope_chain(self) -> None:
        body = {"chain": _SAMPLE_CHAIN, "since": "7d"}
        md = format_markdown(body)
        assert "chain=CH-test" in md

    def test_empty_findings_no_table(self) -> None:
        body = {"org": "example-org", "findings": [], "since": "30d"}
        md = format_markdown(body)
        # No table header when no findings
        assert "| # | Severity |" not in md


# ---------------------------------------------------------------------------
# format_html tests
# ---------------------------------------------------------------------------

class TestFormatHtml:
    def test_doctype_present(self) -> None:
        body = {"org": "example-org", "findings": [], "since": "7d"}
        html = format_html(body)
        assert html.startswith("<!DOCTYPE html>")

    def test_has_style_tag(self) -> None:
        body = {"org": "example-org", "findings": [], "since": "7d"}
        html = format_html(body)
        assert "<style>" in html

    def test_has_report_title(self) -> None:
        body = {"org": "example-org", "findings": _SAMPLE_FINDINGS, "since": "7d"}
        html = format_html(body)
        assert "Aegis Security Report" in html

    def test_severity_classes_present(self) -> None:
        body = {"org": "example-org", "findings": _SAMPLE_FINDINGS, "since": "7d"}
        html = format_html(body)
        assert "sev-critical" in html

    def test_no_xss_in_finding_title(self) -> None:
        """Confirm user-controlled strings are HTML-escaped."""
        xss_finding = {
            "id": "x1",
            "state": "open",
            "scanner": "sast",
            "severity": "high",
            "repo": "example-org/app",
            "title": '<script>alert("xss")</script>',
        }
        body = {"org": "example-org", "findings": [xss_finding], "since": "7d"}
        html = format_html(body)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_table_rows_present(self) -> None:
        body = {"org": "example-org", "findings": _SAMPLE_FINDINGS, "since": "7d"}
        html = format_html(body)
        assert "<tbody>" in html
        assert "<tr>" in html

    def test_chain_section_in_html(self) -> None:
        body = {
            "org": "example-org",
            "findings": [],
            "chains": [_SAMPLE_CHAIN],
            "since": "7d",
        }
        html = format_html(body)
        assert "Active Chains" in html
        assert "RCE-reachable in payments-api" in html

    def test_no_raw_html_in_repo_name(self) -> None:
        """Repo names from backend are also escaped in HTML output."""
        bad_repo_finding = {
            "id": "x2",
            "state": "open",
            "scanner": "deps",
            "severity": "low",
            "repo": "example-org/<evil>",
        }
        body = {"org": "example-org", "findings": [bad_repo_finding], "since": "7d"}
        html = format_html(body)
        assert "<evil>" not in html


# ---------------------------------------------------------------------------
# format_json tests
# ---------------------------------------------------------------------------

class TestFormatJson:
    def test_valid_json(self) -> None:
        body = {"org": "example-org", "findings": _SAMPLE_FINDINGS, "since": "7d"}
        result = format_json(body)
        parsed = json.loads(result)
        assert parsed["org"] == "example-org"
        assert len(parsed["findings"]) == 3

    def test_round_trip(self) -> None:
        body = {"org": "example-org", "findings": _SAMPLE_FINDINGS, "since": "7d"}
        parsed = json.loads(format_json(body))
        assert parsed["findings"][0]["scanner"] == "deps"

    def test_indented_output(self) -> None:
        body = {"org": "example-org", "findings": [], "since": "7d"}
        result = format_json(body)
        # Indented JSON must contain newlines and spaces
        assert "\n" in result
        assert "  " in result

    def test_datetime_objects_serialised(self) -> None:
        from datetime import datetime, timezone
        body = {"org": "example-org", "findings": [], "since": "7d", "ts": datetime.now(timezone.utc)}
        result = format_json(body)
        parsed = json.loads(result)
        assert isinstance(parsed["ts"], str)


# ---------------------------------------------------------------------------
# CLI command tests
# ---------------------------------------------------------------------------

class TestReportCommand:
    @patch("aegis_cli.commands.report.AegisClient")
    @patch("aegis_cli.commands.report.load_config")
    def test_default_markdown_stdout(self, mock_cfg, mock_client_cls) -> None:
        mock_cfg.return_value = _make_cfg()
        mock_client_cls.return_value = _make_client(findings=_SAMPLE_FINDINGS)

        runner = CliRunner()
        result = runner.invoke(cli, ["report"], catch_exceptions=False)

        assert result.exit_code == 0
        assert "# Aegis Security Report" in result.output

    @patch("aegis_cli.commands.report.AegisClient")
    @patch("aegis_cli.commands.report.load_config")
    def test_html_format(self, mock_cfg, mock_client_cls) -> None:
        mock_cfg.return_value = _make_cfg()
        mock_client_cls.return_value = _make_client(findings=_SAMPLE_FINDINGS)

        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--format", "html"], catch_exceptions=False)

        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.output

    @patch("aegis_cli.commands.report.AegisClient")
    @patch("aegis_cli.commands.report.load_config")
    def test_json_format(self, mock_cfg, mock_client_cls) -> None:
        mock_cfg.return_value = _make_cfg()
        mock_client_cls.return_value = _make_client(findings=_SAMPLE_FINDINGS)

        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--format", "json"], catch_exceptions=False)

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "findings" in parsed
        assert len(parsed["findings"]) == 3

    @patch("aegis_cli.commands.report.AegisClient")
    @patch("aegis_cli.commands.report.load_config")
    def test_output_file(self, mock_cfg, mock_client_cls, tmp_path) -> None:
        mock_cfg.return_value = _make_cfg()
        mock_client_cls.return_value = _make_client(findings=_SAMPLE_FINDINGS)
        out_file = tmp_path / "report.md"

        runner = CliRunner()
        result = runner.invoke(
            cli, ["report", "--output", str(out_file)], catch_exceptions=False
        )

        assert result.exit_code == 0
        assert f"Report written to {out_file}" in result.output
        content = out_file.read_text()
        assert "# Aegis Security Report" in content

    @patch("aegis_cli.commands.report.AegisClient")
    @patch("aegis_cli.commands.report.load_config")
    def test_repo_scoped(self, mock_cfg, mock_client_cls) -> None:
        mock_cfg.return_value = _make_cfg()
        client = _make_client(findings=_SAMPLE_FINDINGS)
        mock_client_cls.return_value = client

        runner = CliRunner()
        result = runner.invoke(
            cli, ["report", "--repo", "example-org/payments-api"], catch_exceptions=False
        )

        assert result.exit_code == 0
        # The aggregated endpoint has no repo filter, so the report walks the
        # response and applies the repo filter client-side.
        client.iter_all_findings.assert_called()
        # Only the payments-api findings (2 of 3) should appear in the body
        assert "image-service" not in result.output

    @patch("aegis_cli.commands.report.AegisClient")
    @patch("aegis_cli.commands.report.load_config")
    def test_chain_id_scoped(self, mock_cfg, mock_client_cls) -> None:
        mock_cfg.return_value = _make_cfg()
        client = _make_client(chain=_SAMPLE_CHAIN)
        mock_client_cls.return_value = client

        runner = CliRunner()
        result = runner.invoke(
            cli, ["report", "--chain-id", "CH-test"], catch_exceptions=False
        )

        assert result.exit_code == 0
        client.get_chain.assert_called_once()
        call_kwargs = client.get_chain.call_args.kwargs
        assert call_kwargs.get("chain_id") == "CH-test"

    @patch("aegis_cli.commands.report.AegisClient")
    @patch("aegis_cli.commands.report.load_config")
    def test_severity_filter_passed(self, mock_cfg, mock_client_cls) -> None:
        mock_cfg.return_value = _make_cfg()
        client = _make_client(findings=_SAMPLE_FINDINGS[:1])
        mock_client_cls.return_value = client

        runner = CliRunner()
        runner.invoke(
            cli,
            ["report", "--severity", "critical,high"],
            catch_exceptions=False,
        )

        call_kwargs = client.iter_all_findings.call_args.kwargs
        assert call_kwargs.get("severity") == ["critical", "high"]

    @patch("aegis_cli.commands.report.AegisClient")
    @patch("aegis_cli.commands.report.load_config")
    def test_no_token_exits(self, mock_cfg, mock_client_cls) -> None:
        mock_cfg.return_value = _make_cfg(token="")
        runner = CliRunner()
        result = runner.invoke(cli, ["report"])
        assert result.exit_code != 0

    @patch("aegis_cli.commands.report.AegisClient")
    @patch("aegis_cli.commands.report.load_config")
    def test_since_default(self, mock_cfg, mock_client_cls) -> None:
        mock_cfg.return_value = _make_cfg()
        mock_client_cls.return_value = _make_client(findings=[])

        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--format", "json"], catch_exceptions=False)

        parsed = json.loads(result.output)
        assert parsed.get("since") == "7d"

    @patch("aegis_cli.commands.report.AegisClient")
    @patch("aegis_cli.commands.report.load_config")
    def test_custom_since(self, mock_cfg, mock_client_cls) -> None:
        mock_cfg.return_value = _make_cfg()
        mock_client_cls.return_value = _make_client(findings=[])

        runner = CliRunner()
        result = runner.invoke(
            cli, ["report", "--since", "30d", "--format", "json"], catch_exceptions=False
        )

        parsed = json.loads(result.output)
        assert parsed.get("since") == "30d"

    @patch("aegis_cli.commands.report.AegisClient")
    @patch("aegis_cli.commands.report.load_config")
    def test_org_override(self, mock_cfg, mock_client_cls) -> None:
        mock_cfg.return_value = _make_cfg(org=None)
        client = _make_client(findings=[])
        mock_client_cls.return_value = client

        runner = CliRunner()
        runner.invoke(
            cli, ["report", "--org", "other-org"], catch_exceptions=False
        )

        call_kwargs = client.iter_all_findings.call_args.kwargs
        assert call_kwargs.get("org") == "other-org"

