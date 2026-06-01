"""Tests for aegis sbom export / history subcommands."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aegis_cli.main import cli
from aegis_cli.client import AegisAPIError


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_cfg(token="test-token", org="example-org"):
    cfg = MagicMock()
    cfg.base_url = "https://aegis.example.org"
    cfg.api_token = token
    cfg.default_org = org
    return cfg


def _run(*args, env=None):
    runner = CliRunner()
    return runner.invoke(cli, list(args), catch_exceptions=False, env=env or {})


def _make_client_mock(export_return="<sbom>", history_return=None):
    client_inst = MagicMock()
    client_inst.__enter__ = lambda s: client_inst
    client_inst.__exit__ = MagicMock(return_value=False)
    client_inst.export_sbom.return_value = export_return
    client_inst.list_sbom_history.return_value = history_return or []
    return client_inst


SAMPLE_CDX_JSON = '{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}'
SAMPLE_SPDX_JSON = '{"spdxVersion":"SPDX-2.3","packages":[]}'
SAMPLE_CDX_XML = "<?xml version='1.0'?><bom/>"
SAMPLE_TAG_VALUE = "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n"


# ── aegis sbom export ─────────────────────────────────────────────────────────

@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_export_repo_cyclonedx_json_to_stdout(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client_mock(export_return=SAMPLE_CDX_JSON)
    mock_client_cls.return_value = client_inst

    result = _run("sbom", "export", "--repo", "example-org/payments-api")

    assert result.exit_code == 0
    assert "CycloneDX" in result.output
    client_inst.export_sbom.assert_called_once_with(
        repo="example-org/payments-api",
        image_digest=None,
        format="cyclonedx-json",
    )


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_export_image_digest(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client_mock(export_return=SAMPLE_CDX_JSON)
    mock_client_cls.return_value = client_inst

    result = _run(
        "sbom", "export",
        "--image-digest", "sha256:deadbeef0000",
    )

    assert result.exit_code == 0
    client_inst.export_sbom.assert_called_once_with(
        repo=None,
        image_digest="sha256:deadbeef0000",
        format="cyclonedx-json",
    )


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_export_format_spdx_json(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client_mock(export_return=SAMPLE_SPDX_JSON)
    mock_client_cls.return_value = client_inst

    result = _run(
        "sbom", "export",
        "--repo", "example-org/payments-api",
        "--format", "spdx-json",
    )

    assert result.exit_code == 0
    assert "SPDX" in result.output
    client_inst.export_sbom.assert_called_once_with(
        repo="example-org/payments-api",
        image_digest=None,
        format="spdx-json",
    )


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_export_format_cyclonedx_xml(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client_mock(export_return=SAMPLE_CDX_XML)
    mock_client_cls.return_value = client_inst

    result = _run(
        "sbom", "export",
        "--repo", "example-org/payments-api",
        "--format", "cyclonedx-xml",
    )

    assert result.exit_code == 0
    client_inst.export_sbom.assert_called_once_with(
        repo="example-org/payments-api",
        image_digest=None,
        format="cyclonedx-xml",
    )


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_export_format_spdx_tag_value(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client_mock(export_return=SAMPLE_TAG_VALUE)
    mock_client_cls.return_value = client_inst

    result = _run(
        "sbom", "export",
        "--repo", "example-org/payments-api",
        "--format", "spdx-tag-value",
    )

    assert result.exit_code == 0
    assert "SPDXVersion" in result.output


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_export_to_file(mock_cfg, mock_client_cls, tmp_path):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client_mock(export_return=SAMPLE_CDX_JSON)
    mock_client_cls.return_value = client_inst

    output_file = tmp_path / "sbom.json"
    result = _run(
        "sbom", "export",
        "--repo", "example-org/payments-api",
        "--output", str(output_file),
    )

    assert result.exit_code == 0
    assert output_file.exists()
    assert "CycloneDX" in output_file.read_text()
    assert "written" in result.output.lower()


def test_export_invalid_format():
    result = _run("sbom", "export", "--repo", "example-org/repo", "--format", "csv")
    assert result.exit_code != 0


def test_export_missing_repo_and_digest():
    runner = CliRunner()
    with patch("aegis_cli.commands.sbom.load_config") as mock_cfg:
        mock_cfg.return_value = _make_cfg()
        result = runner.invoke(cli, ["sbom", "export"], catch_exceptions=False)
    assert result.exit_code != 0
    assert "repo" in result.output.lower() or "error" in result.output.lower()


def test_export_repo_and_digest_mutually_exclusive():
    runner = CliRunner()
    with patch("aegis_cli.commands.sbom.load_config") as mock_cfg:
        mock_cfg.return_value = _make_cfg()
        result = runner.invoke(
            cli,
            [
                "sbom", "export",
                "--repo", "example-org/repo",
                "--image-digest", "sha256:abc",
            ],
            catch_exceptions=False,
        )
    assert result.exit_code != 0


def test_export_no_token():
    runner = CliRunner()
    with patch("aegis_cli.commands.sbom.load_config") as mock_cfg:
        cfg = _make_cfg(token="")
        mock_cfg.return_value = cfg
        result = runner.invoke(
            cli,
            ["sbom", "export", "--repo", "example-org/repo"],
            catch_exceptions=False,
        )
    assert result.exit_code != 0
    assert "token" in result.output.lower() or "error" in result.output.lower()


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_export_api_error_exits_nonzero(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client_mock()
    client_inst.export_sbom.side_effect = AegisAPIError("not found", status_code=404)
    mock_client_cls.return_value = client_inst

    result = _run("sbom", "export", "--repo", "example-org/payments-api")

    assert result.exit_code != 0
    assert "error" in result.output.lower() or "not found" in result.output.lower()


# ── aegis sbom history ────────────────────────────────────────────────────────

@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_history_no_entries(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client_mock(history_return=[])
    mock_client_cls.return_value = client_inst

    result = _run("sbom", "history", "--repo", "example-org/payments-api")

    assert result.exit_code == 0
    assert "no sbom history" in result.output.lower()


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_history_table_output(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    history = [
        {
            "manifest_set_hash": "aabbcc" * 10,
            "created_at": "2025-01-01T00:00:00+00:00",
            "blob_pointer": "s3://sboms/...",
            "content_hash": "sha256abc",
            "tool_version": "syft-1.0.0",
        }
    ]
    client_inst = _make_client_mock(history_return=history)
    mock_client_cls.return_value = client_inst

    result = _run("sbom", "history", "--repo", "example-org/payments-api")

    assert result.exit_code == 0
    assert "aabbcc" in result.output
    assert "syft-1.0.0" in result.output
    assert "2025-01-01" in result.output


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_history_json_output(mock_cfg, mock_client_cls):
    import json as _json

    mock_cfg.return_value = _make_cfg()
    history = [
        {
            "manifest_set_hash": "aabbcc" * 10,
            "created_at": "2025-01-01T00:00:00+00:00",
            "blob_pointer": "s3://sboms/...",
            "content_hash": "sha256abc",
            "tool_version": "syft-1.0.0",
        }
    ]
    client_inst = _make_client_mock(history_return=history)
    mock_client_cls.return_value = client_inst

    result = _run(
        "sbom", "history",
        "--repo", "example-org/payments-api",
        "--json",
    )

    assert result.exit_code == 0
    parsed = _json.loads(result.output)
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    assert parsed[0]["manifest_set_hash"] == "aabbcc" * 10


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_history_limit_applied(mock_cfg, mock_client_cls):
    import json as _json

    mock_cfg.return_value = _make_cfg()
    history = [
        {
            "manifest_set_hash": f"hash{i:02d}" * 8,
            "created_at": f"2025-0{i+1}-01T00:00:00+00:00",
            "blob_pointer": f"s3://sboms/{i}",
            "content_hash": f"sha{i}",
            "tool_version": "syft-1.0.0",
        }
        for i in range(5)
    ]
    client_inst = _make_client_mock(history_return=history)
    mock_client_cls.return_value = client_inst

    result = _run(
        "sbom", "history",
        "--repo", "example-org/payments-api",
        "--limit", "2",
        "--json",
    )

    assert result.exit_code == 0
    parsed = _json.loads(result.output)
    assert len(parsed) == 2


@patch("aegis_cli.commands.sbom.AegisClient")
@patch("aegis_cli.commands.sbom.load_config")
def test_history_api_error_exits_nonzero(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client_mock()
    client_inst.list_sbom_history.side_effect = AegisAPIError("server error", status_code=500)
    mock_client_cls.return_value = client_inst

    result = _run("sbom", "history", "--repo", "example-org/payments-api")

    assert result.exit_code != 0


def test_history_requires_repo():
    runner = CliRunner()
    with patch("aegis_cli.commands.sbom.load_config") as mock_cfg:
        mock_cfg.return_value = _make_cfg()
        result = runner.invoke(cli, ["sbom", "history"], catch_exceptions=False)
    assert result.exit_code != 0


# ── aegis sbom --help ─────────────────────────────────────────────────────────

def test_sbom_help_shows_subcommands():
    result = _run("sbom", "--help")
    assert result.exit_code == 0
    assert "export" in result.output
    assert "history" in result.output


def test_export_help_shows_options():
    result = _run("sbom", "export", "--help")
    assert result.exit_code == 0
    assert "--repo" in result.output
    assert "--format" in result.output
    assert "--output" in result.output


def test_history_help_shows_options():
    result = _run("sbom", "history", "--help")
    assert result.exit_code == 0
    assert "--repo" in result.output
    assert "--limit" in result.output
    assert "--json" in result.output
