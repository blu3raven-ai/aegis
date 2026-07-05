"""CLI invocation tests for aegis comment."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aegis_cli.main import cli
from aegis_cli.client import AegisAPIError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cfg(org: str = "example-org", token: str = "testtoken") -> MagicMock:
    cfg = MagicMock()
    cfg.base_url = "https://aegis.example.org"
    cfg.api_token = token
    cfg.default_org = org
    return cfg


def _make_client(findings=None, side_effect=None) -> MagicMock:
    """Build a mock AegisClient.

    Pass *findings* for the iter_all_findings return value, or *side_effect*
    to raise from iter_all_findings.
    """
    inst = MagicMock()
    inst.__enter__ = lambda s: inst
    inst.__exit__ = MagicMock(return_value=False)
    if side_effect:
        inst.iter_all_findings.side_effect = side_effect
    else:
        inst.iter_all_findings.return_value = findings if findings is not None else []
    return inst


# Flat-shape findings as returned by GET /api/v1/findings.
_SAMPLE_FINDINGS = [
    {
        "id": "fnd-1",
        "scanner": "deps",
        "severity": "critical",
        "state": "open",
        "title": "RCE via log4j reachable from HTTP endpoint",
        "cve": "CVE-2026-3471",
        "package": "log4j@2.14.1",
        "repo": "example-org/payments-api",
    },
    {
        "id": "fnd-2",
        "scanner": "sast",
        "severity": "high",
        "state": "open",
        "title": "SSRF in image proxy",
        "repo": "example-org/image-service",
    },
    {
        "id": "fnd-3",
        "scanner": "secrets",
        "severity": "medium",
        "state": "open",
        "title": "Exposed API key",
        "repo": "example-org/api-service",
    },
]


# ---------------------------------------------------------------------------
# Basic invocation
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.comment.AegisClient")
@patch("aegis_cli.commands.comment.load_config")
def test_comment_default_github_stdout(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(findings=_SAMPLE_FINDINGS)

    runner = CliRunner()
    result = runner.invoke(cli, ["comment"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "## 🛡️ Aegis Security Report" in result.output


@patch("aegis_cli.commands.comment.AegisClient")
@patch("aegis_cli.commands.comment.load_config")
def test_comment_gitlab_format(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(findings=_SAMPLE_FINDINGS)

    runner = CliRunner()
    result = runner.invoke(cli, ["comment", "--format", "gitlab"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "## 🛡️ Aegis Security Report" in result.output
    assert "<details>" in result.output


@patch("aegis_cli.commands.comment.AegisClient")
@patch("aegis_cli.commands.comment.load_config")
def test_comment_bitbucket_format(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(findings=_SAMPLE_FINDINGS)

    runner = CliRunner()
    result = runner.invoke(cli, ["comment", "--format", "bitbucket"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "## Aegis Security Report" in result.output
    assert "<details>" not in result.output


# ---------------------------------------------------------------------------
# --include-chains and --include-decision flags
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.comment.AegisClient")
@patch("aegis_cli.commands.comment.load_config")
def test_include_decision_block(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    # Critical findings → decision must be block
    mock_client_cls.return_value = _make_client(findings=_SAMPLE_FINDINGS)

    runner = CliRunner()
    result = runner.invoke(cli, ["comment", "--include-decision"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "### Decision:" in result.output
    assert "❌ Block" in result.output


@patch("aegis_cli.commands.comment.AegisClient")
@patch("aegis_cli.commands.comment.load_config")
def test_include_decision_allow(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    low_only = [
        {"id": "fnd-low", "scanner": "sast", "severity": "low", "state": "open", "title": "Minor lint issue"}
    ]
    mock_client_cls.return_value = _make_client(findings=low_only)

    runner = CliRunner()
    result = runner.invoke(cli, ["comment", "--include-decision"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "✅ Allow" in result.output


@patch("aegis_cli.commands.comment.AegisClient")
@patch("aegis_cli.commands.comment.load_config")
def test_include_chains_no_embedded_chains(mock_cfg, mock_client_cls):
    """--include-chains with no chain data in findings emits an empty chains section."""
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(findings=_SAMPLE_FINDINGS)

    runner = CliRunner()
    result = runner.invoke(cli, ["comment", "--include-chains"], catch_exceptions=False)

    assert result.exit_code == 0
    # No chains in these findings — chains section should not appear
    assert "### Chains" not in result.output


# ---------------------------------------------------------------------------
# --max-findings
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.comment.AegisClient")
@patch("aegis_cli.commands.comment.load_config")
def test_max_findings_limits_display(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    # 5 critical findings
    many_findings = [
        {
            "id": f"fnd-many-{i}",
            "scanner": "sast",
            "severity": "critical",
            "state": "open",
            "title": f"Critical finding {i}",
        }
        for i in range(5)
    ]
    mock_client_cls.return_value = _make_client(findings=many_findings)

    runner = CliRunner()
    result = runner.invoke(cli, ["comment", "--max-findings", "2"], catch_exceptions=False)

    assert result.exit_code == 0
    # Total count still shows 5 (real total)
    assert "5 findings" in result.output


# ---------------------------------------------------------------------------
# --output flag
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.comment.AegisClient")
@patch("aegis_cli.commands.comment.load_config")
def test_output_writes_file(mock_cfg, mock_client_cls, tmp_path):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(findings=_SAMPLE_FINDINGS)
    out_file = tmp_path / "comment.md"

    runner = CliRunner()
    result = runner.invoke(
        cli, ["comment", "--output", str(out_file)], catch_exceptions=False
    )

    assert result.exit_code == 0
    assert f"Comment written to {out_file}" in result.output
    content = out_file.read_text()
    assert "## 🛡️ Aegis Security Report" in content


# ---------------------------------------------------------------------------
# --from-json flag
# ---------------------------------------------------------------------------

def test_from_json_list_format(tmp_path):
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(_SAMPLE_FINDINGS), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["comment", "--from-json", str(findings_file)],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    assert "## 🛡️ Aegis Security Report" in result.output
    assert "RCE via log4j" in result.output


def test_from_json_envelope_format(tmp_path):
    """Accept {"findings": [...]} envelope in addition to a bare list."""
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(
        json.dumps({"findings": _SAMPLE_FINDINGS, "scan_id": "s-001"}),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["comment", "--from-json", str(findings_file)],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    assert "## 🛡️ Aegis Security Report" in result.output


def test_from_json_invalid_json_exits(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("this is not json", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["comment", "--from-json", str(bad_file)])

    assert result.exit_code != 0


def test_from_json_wrong_shape_exits(tmp_path):
    bad_file = tmp_path / "wrong.json"
    bad_file.write_text(json.dumps({"something": "else"}), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["comment", "--from-json", str(bad_file)])

    assert result.exit_code != 0


def test_from_json_severity_filter(tmp_path):
    """--severity filter is applied when reading from a JSON file."""
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(_SAMPLE_FINDINGS), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["comment", "--from-json", str(findings_file), "--severity", "medium"],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    # Critical / high findings should be filtered out, so no critical badge
    assert "🔴 Critical" not in result.output


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.comment.load_config")
def test_no_token_exits(mock_cfg):
    mock_cfg.return_value = _make_cfg(token="")

    runner = CliRunner()
    result = runner.invoke(cli, ["comment"])

    assert result.exit_code != 0
    assert "API token" in result.output or "API token" in (result.stderr or "")


@patch("aegis_cli.commands.comment.load_config")
def test_no_org_exits(mock_cfg):
    mock_cfg.return_value = _make_cfg(org=None)

    runner = CliRunner()
    result = runner.invoke(cli, ["comment"])

    assert result.exit_code != 0


@patch("aegis_cli.commands.comment.AegisClient")
@patch("aegis_cli.commands.comment.load_config")
def test_api_error_exits(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(
        side_effect=AegisAPIError("server error", status_code=500)
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["comment"])

    assert result.exit_code != 0


@patch("aegis_cli.commands.comment.AegisClient")
@patch("aegis_cli.commands.comment.load_config")
def test_empty_findings_renders_gracefully(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(findings=[])

    runner = CliRunner()
    result = runner.invoke(cli, ["comment"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "_No findings in this scan._" in result.output


@patch("aegis_cli.commands.comment.AegisClient")
@patch("aegis_cli.commands.comment.load_config")
def test_repo_filter_applied_client_side(mock_cfg, mock_client_cls):
    """--repo is filtered client-side against the aggregated response."""
    mock_cfg.return_value = _make_cfg()
    client = _make_client(findings=_SAMPLE_FINDINGS)
    mock_client_cls.return_value = client

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["comment", "--repo", "example-org/payments-api"],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    # Only the payments-api finding remains; total count reflects the filter.
    assert "1 finding" in result.output
    assert "image-service" not in result.output
