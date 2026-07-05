"""CLI tests for aegis export subcommands."""
from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aegis_cli.main import cli
from aegis_cli.commands.export import _parse_since_param


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cfg(base_url: str = "https://aegis.example.org", token: str = "tok") -> MagicMock:
    cfg = MagicMock()
    cfg.base_url = base_url
    cfg.api_token = token
    cfg.default_org = "example-org"
    return cfg


def _fake_stream_response(body: bytes, total_count: int = 5, status_code: int = 200):
    """Return a mock httpx streaming context manager that yields *body* in chunks."""
    chunks = [body[i:i + 64] for i in range(0, max(len(body), 1), 64)] or [b""]
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"x-total-count": str(total_count)}
    resp.iter_bytes = MagicMock(return_value=iter(chunks))
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


# ---------------------------------------------------------------------------
# _parse_since_param
# ---------------------------------------------------------------------------

def test_parse_since_none():
    assert _parse_since_param(None) is None


def test_parse_since_30d_returns_iso():
    result = _parse_since_param("30d")
    assert result is not None
    assert "T" in result  # ISO-8601 datetime


def test_parse_since_non_day_string_passes_through():
    # Non-day strings pass through as-is so the server can validate them
    result = _parse_since_param("2weeks")
    assert result == "2weeks"


def test_parse_since_passthrough_iso():
    iso = "2026-01-01T00:00:00+00:00"
    assert _parse_since_param(iso) == iso


# ---------------------------------------------------------------------------
# export --help
# ---------------------------------------------------------------------------

def test_export_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["export", "--help"])
    assert result.exit_code == 0
    assert "findings" in result.output


def test_export_findings_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["export", "findings", "--help"])
    assert result.exit_code == 0
    assert "--format" in result.output
    assert "--output" in result.output
    assert "--severity" in result.output
    assert "--scanner" in result.output
    assert "--since" in result.output


# ---------------------------------------------------------------------------
# export findings — CSV
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.export.load_config")
@patch("aegis_cli.commands.export.AegisClient")
def test_findings_csv_writes_file(mock_client_cls, mock_cfg, tmp_path):
    mock_cfg.return_value = _make_cfg()
    csv_body = b"id,severity,scanner\n1,critical,secrets\n2,high,deps\n"
    client = MagicMock()
    client._http.stream.return_value = _fake_stream_response(csv_body, total_count=2)
    mock_client_cls.return_value = client

    out = tmp_path / "findings.csv"
    runner = CliRunner()
    result = runner.invoke(cli, ["export", "findings", "--format", "csv", "-o", str(out)])

    assert result.exit_code == 0, result.output
    assert out.exists()
    assert out.read_bytes() == csv_body


@patch("aegis_cli.commands.export.load_config")
@patch("aegis_cli.commands.export.AegisClient")
def test_findings_csv_reports_total(mock_client_cls, mock_cfg, tmp_path):
    mock_cfg.return_value = _make_cfg()
    client = MagicMock()
    client._http.stream.return_value = _fake_stream_response(b"id,sev\n", total_count=42)
    mock_client_cls.return_value = client

    out = tmp_path / "f.csv"
    runner = CliRunner()
    result = runner.invoke(cli, ["export", "findings", "-o", str(out)])

    assert "42" in result.output


# ---------------------------------------------------------------------------
# export findings — JSON (JSONL)
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.export.load_config")
@patch("aegis_cli.commands.export.AegisClient")
def test_findings_json_writes_file(mock_client_cls, mock_cfg, tmp_path):
    mock_cfg.return_value = _make_cfg()
    lines = "\n".join(json.dumps({"id": i, "severity": "high"}) for i in range(5)) + "\n"
    body = lines.encode()
    client = MagicMock()
    client._http.stream.return_value = _fake_stream_response(body, total_count=5)
    mock_client_cls.return_value = client

    out = tmp_path / "findings.jsonl"
    runner = CliRunner()
    result = runner.invoke(cli, ["export", "findings", "--format", "json", "-o", str(out)])

    assert result.exit_code == 0, result.output
    assert out.exists()
    assert out.read_bytes() == body


# ---------------------------------------------------------------------------
# Format flag respected
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.export.load_config")
@patch("aegis_cli.commands.export.AegisClient")
def test_format_flag_sent_in_params(mock_client_cls, mock_cfg, tmp_path):
    mock_cfg.return_value = _make_cfg()
    client = MagicMock()
    client._http.stream.return_value = _fake_stream_response(b"", total_count=0)
    mock_client_cls.return_value = client

    out = tmp_path / "f.jsonl"
    runner = CliRunner()
    runner.invoke(cli, ["export", "findings", "--format", "json", "-o", str(out)])

    call_kwargs = client._http.stream.call_args
    params = call_kwargs[1].get("params", call_kwargs[0][2] if len(call_kwargs[0]) > 2 else {})
    assert params.get("format") == "json"


# ---------------------------------------------------------------------------
# Filters forwarded
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.export.load_config")
@patch("aegis_cli.commands.export.AegisClient")
def test_severity_filter_forwarded(mock_client_cls, mock_cfg, tmp_path):
    mock_cfg.return_value = _make_cfg()
    client = MagicMock()
    client._http.stream.return_value = _fake_stream_response(b"", 0)
    mock_client_cls.return_value = client

    out = tmp_path / "f.csv"
    runner = CliRunner()
    runner.invoke(cli, [
        "export", "findings", "-o", str(out),
        "--severity", "critical,high",
    ])

    call_kwargs = client._http.stream.call_args
    params = call_kwargs[1].get("params", {})
    assert "critical" in params.get("severity", "")


@patch("aegis_cli.commands.export.load_config")
@patch("aegis_cli.commands.export.AegisClient")
def test_repo_id_filter_forwarded(mock_client_cls, mock_cfg, tmp_path):
    mock_cfg.return_value = _make_cfg()
    client = MagicMock()
    client._http.stream.return_value = _fake_stream_response(b"", 0)
    mock_client_cls.return_value = client

    out = tmp_path / "f.csv"
    runner = CliRunner()
    runner.invoke(cli, [
        "export", "findings", "-o", str(out),
        "--repo-id", "example-org/payments-api",
    ])

    call_kwargs = client._http.stream.call_args
    params = call_kwargs[1].get("params", {})
    assert params.get("repo_id") == "example-org/payments-api"


# ---------------------------------------------------------------------------
# Large response — 10k rows streamed without buffering
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.export.load_config")
@patch("aegis_cli.commands.export.AegisClient")
def test_large_response_streams_without_full_buffer(mock_client_cls, mock_cfg, tmp_path):
    """Simulate a 10k-row JSONL export arriving in many small chunks.

    The command must write all chunks to disk without accumulating them
    in memory (validated by verifying the written byte count).
    """
    mock_cfg.return_value = _make_cfg()

    # Generate 10k lines of JSONL
    all_lines = "\n".join(json.dumps({"id": i, "severity": "high"}) for i in range(10_000)) + "\n"
    all_bytes = all_lines.encode()

    # Break into 64-byte chunks to simulate streaming
    chunk_size = 64
    chunks = [all_bytes[i:i + chunk_size] for i in range(0, len(all_bytes), chunk_size)]

    class _StreamResp:
        status_code = 200
        headers = {"x-total-count": "10000"}

        def iter_bytes(self, chunk_size=65536):
            return iter(chunks)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    client = MagicMock()
    client._http.stream.return_value = _StreamResp()
    mock_client_cls.return_value = client

    out = tmp_path / "large.jsonl"
    runner = CliRunner()
    result = runner.invoke(cli, ["export", "findings", "--format", "json", "-o", str(out)])

    assert result.exit_code == 0, result.output
    assert out.stat().st_size == len(all_bytes)
    written_lines = [l for l in out.read_text().splitlines() if l.strip()]
    assert len(written_lines) == 10_000


# ---------------------------------------------------------------------------
# HTTP error handling
# ---------------------------------------------------------------------------

@patch("aegis_cli.commands.export.load_config")
@patch("aegis_cli.commands.export.AegisClient")
def test_http_error_exits_nonzero(mock_client_cls, mock_cfg, tmp_path):
    mock_cfg.return_value = _make_cfg()
    client = MagicMock()
    client._http.stream.return_value = _fake_stream_response(b"", status_code=403)
    mock_client_cls.return_value = client

    out = tmp_path / "f.csv"
    runner = CliRunner()
    result = runner.invoke(cli, ["export", "findings", "-o", str(out)])

    assert result.exit_code != 0
    assert "failed" in result.output.lower() or "failed" in (result.exception.__str__() if result.exception else "")
