"""Tests for aegis sbom diff subcommand — Phase 37."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aegis_cli.main import cli
from aegis_cli.client import AegisAPIError


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_cfg(token="test-token"):
    cfg = MagicMock()
    cfg.base_url = "https://aegis.example.org"
    cfg.api_token = token
    return cfg


def _run(*args):
    runner = CliRunner()
    return runner.invoke(cli, list(args), catch_exceptions=False)


def _make_client_mock(diff_return: dict | None = None):
    client_inst = MagicMock()
    client_inst.__enter__ = lambda s: client_inst
    client_inst.__exit__ = MagicMock(return_value=False)
    client_inst.diff_sbom.return_value = diff_return or {
        "added": [],
        "removed": [],
        "version_changed": [],
        "unchanged_count": 0,
    }
    return client_inst


SAMPLE_DIFF: dict = {
    "added": [
        {"name": "lodash", "version": "4.17.21", "type": "library"},
        {"name": "axios", "version": "1.4.0", "type": "library"},
        {"name": "react", "version": "18.2.0", "type": "library"},
    ],
    "removed": [
        {"name": "jquery", "version": "3.6.0", "type": "library"},
    ],
    "version_changed": [
        {"name": "express", "purl": "", "from_version": "4.18.0", "to_version": "4.18.2"},
        {"name": "webpack", "purl": "", "from_version": "5.78.0", "to_version": "5.79.0"},
    ],
    "unchanged_count": 487,
}

REPO = "example-org/payments-api"
FROM_HASH = "aabbcc" * 10 + "aa"
TO_HASH = "ddeeff" * 10 + "dd"


# ── happy path — text format ──────────────────────────────────────────────────

@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_diff_text_output_structure(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client_mock(diff_return=SAMPLE_DIFF)

    result = _run("sbom", "diff", "--repo", REPO, "--from-hash", FROM_HASH, "--to-hash", TO_HASH)

    assert result.exit_code == 0
    output = result.output
    assert "SBOM diff:" in output
    assert "example-org/payments-api" in output
    # truncated hash should appear
    assert FROM_HASH[:12] in output
    assert TO_HASH[:12] in output
    assert "Added:" in output
    assert "Removed:" in output
    assert "Version changed:" in output
    assert "Unchanged:" in output


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_diff_text_shows_added_packages(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client_mock(diff_return=SAMPLE_DIFF)

    result = _run("sbom", "diff", "--repo", REPO, "--from-hash", FROM_HASH, "--to-hash", TO_HASH)

    assert result.exit_code == 0
    assert "+ lodash@4.17.21" in result.output
    assert "+ axios@1.4.0" in result.output
    assert "+ react@18.2.0" in result.output


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_diff_text_shows_removed_packages(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client_mock(diff_return=SAMPLE_DIFF)

    result = _run("sbom", "diff", "--repo", REPO, "--from-hash", FROM_HASH, "--to-hash", TO_HASH)

    assert result.exit_code == 0
    assert "- jquery@3.6.0" in result.output


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_diff_text_shows_version_changes(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client_mock(diff_return=SAMPLE_DIFF)

    result = _run("sbom", "diff", "--repo", REPO, "--from-hash", FROM_HASH, "--to-hash", TO_HASH)

    assert result.exit_code == 0
    assert "express" in result.output
    assert "4.18.0" in result.output
    assert "4.18.2" in result.output
    assert "webpack" in result.output


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_diff_text_shows_unchanged_count(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client_mock(diff_return=SAMPLE_DIFF)

    result = _run("sbom", "diff", "--repo", REPO, "--from-hash", FROM_HASH, "--to-hash", TO_HASH)

    assert result.exit_code == 0
    assert "487" in result.output


# ── json format ───────────────────────────────────────────────────────────────

@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_diff_json_format_is_valid_json(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client_mock(diff_return=SAMPLE_DIFF)

    result = _run(
        "sbom", "diff",
        "--repo", REPO, "--from-hash", FROM_HASH, "--to-hash", TO_HASH,
        "--format", "json",
    )

    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert "added" in parsed
    assert "removed" in parsed
    assert "version_changed" in parsed
    assert "unchanged_count" in parsed
    assert parsed["unchanged_count"] == 487


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_diff_json_format_preserves_full_payload(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client_mock(diff_return=SAMPLE_DIFF)

    result = _run(
        "sbom", "diff",
        "--repo", REPO, "--from-hash", FROM_HASH, "--to-hash", TO_HASH,
        "--format", "json",
    )

    parsed = json.loads(result.output)
    assert len(parsed["added"]) == 3
    assert len(parsed["removed"]) == 1
    assert len(parsed["version_changed"]) == 2


# ── markdown format ───────────────────────────────────────────────────────────

@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_diff_markdown_format_structure(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client_mock(diff_return=SAMPLE_DIFF)

    result = _run(
        "sbom", "diff",
        "--repo", REPO, "--from-hash", FROM_HASH, "--to-hash", TO_HASH,
        "--format", "markdown",
    )

    assert result.exit_code == 0
    output = result.output
    assert "## SBOM diff" in output
    assert "### Added" in output
    assert "### Removed" in output
    assert "### Version changed" in output
    assert "### Unchanged" in output


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_diff_markdown_shows_added_in_backticks(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client_mock(diff_return=SAMPLE_DIFF)

    result = _run(
        "sbom", "diff",
        "--repo", REPO, "--from-hash", FROM_HASH, "--to-hash", TO_HASH,
        "--format", "markdown",
    )

    assert "`lodash@4.17.21`" in result.output
    assert "`jquery@3.6.0`" in result.output


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_diff_markdown_empty_sections_show_none(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    empty_diff = {"added": [], "removed": [], "version_changed": [], "unchanged_count": 5}
    mock_client_cls.return_value = _make_client_mock(diff_return=empty_diff)

    result = _run(
        "sbom", "diff",
        "--repo", REPO, "--from-hash", FROM_HASH, "--to-hash", TO_HASH,
        "--format", "markdown",
    )

    assert result.exit_code == 0
    assert "_None_" in result.output


# ── client call args ─────────────────────────────────────────────────────────

@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_diff_passes_correct_args_to_client(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client_mock()
    mock_client_cls.return_value = client_inst

    _run("sbom", "diff", "--repo", REPO, "--from-hash", FROM_HASH, "--to-hash", TO_HASH)

    client_inst.diff_sbom.assert_called_once_with(
        repo_id=REPO,
        from_hash=FROM_HASH,
        to_hash=TO_HASH,
    )


# ── error handling ────────────────────────────────────────────────────────────

@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_diff_api_error_exits_nonzero(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client_mock()
    client_inst.diff_sbom.side_effect = AegisAPIError("not found", status_code=404)
    mock_client_cls.return_value = client_inst

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["sbom", "diff", "--repo", REPO, "--from-hash", FROM_HASH, "--to-hash", TO_HASH],
        catch_exceptions=False,
    )

    assert result.exit_code != 0


def test_diff_no_token_exits_nonzero():
    runner = CliRunner()
    with patch("aegis_cli.commands.sbom.load_config") as mock_cfg:
        mock_cfg.return_value = _make_cfg(token="")
        result = runner.invoke(
            cli,
            ["sbom", "diff", "--repo", REPO, "--from-hash", FROM_HASH, "--to-hash", TO_HASH],
            catch_exceptions=False,
        )
    assert result.exit_code != 0
    assert "token" in result.output.lower() or "error" in result.output.lower()


def test_diff_requires_repo():
    result = _run("sbom", "diff", "--from-hash", FROM_HASH, "--to-hash", TO_HASH)
    assert result.exit_code != 0


def test_diff_requires_from_hash():
    result = _run("sbom", "diff", "--repo", REPO, "--to-hash", TO_HASH)
    assert result.exit_code != 0


def test_diff_requires_to_hash():
    result = _run("sbom", "diff", "--repo", REPO, "--from-hash", FROM_HASH)
    assert result.exit_code != 0


# ── help text ─────────────────────────────────────────────────────────────────

def test_diff_help_shows_options():
    result = _run("sbom", "diff", "--help")
    assert result.exit_code == 0
    assert "--repo" in result.output
    assert "--from-hash" in result.output
    assert "--to-hash" in result.output
    assert "--format" in result.output


def test_sbom_help_shows_diff_subcommand():
    result = _run("sbom", "--help")
    assert result.exit_code == 0
    assert "diff" in result.output
