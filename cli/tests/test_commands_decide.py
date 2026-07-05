"""Tests for aegis decide command — including local heuristic fallback path."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aegis_cli.main import cli
from aegis_cli.client import AegisAPIError


def _make_cfg(org="example-org", token="tok"):
    cfg = MagicMock()
    cfg.base_url = "https://aegis.example.org"
    cfg.api_token = token
    cfg.default_org = org
    return cfg


def _make_client(decision_return=None, side_effect=None):
    client_inst = MagicMock()
    client_inst.__enter__ = lambda s: client_inst
    client_inst.__exit__ = MagicMock(return_value=False)
    if side_effect:
        client_inst.get_decision.side_effect = side_effect
    else:
        client_inst.get_decision.return_value = decision_return or {}
    return client_inst


# ---------------------------------------------------------------------------
# Allow decision
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.decide.AegisClient")
@patch("aegis_cli.commands.decide.load_config")
def test_decide_allow_prints_and_exits_0(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(
        decision_return={"decision": "allow", "blockers": [], "rationale": "clean"}
    )
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["decide", "--org", "example-org", "--repo", "example-org/svc", "--exit-code"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "allow" in result.output.lower()


# ---------------------------------------------------------------------------
# Block decision
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.decide.AegisClient")
@patch("aegis_cli.commands.decide.load_config")
def test_decide_block_exits_1_with_exit_code_flag(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(
        decision_return={
            "decision": "block",
            "blockers": [{"state": "open", "security_advisory": {"severity": "critical"}}],
            "rationale": "critical finding present",
        }
    )
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["decide", "--org", "example-org", "--repo", "example-org/svc", "--exit-code"],
        catch_exceptions=False,
    )
    assert result.exit_code == 1
    assert "block" in result.output.lower()


@patch("aegis_cli.commands.decide.AegisClient")
@patch("aegis_cli.commands.decide.load_config")
def test_decide_block_without_exit_code_flag_still_exits_0(mock_cfg, mock_client_cls):
    """Without --exit-code, a block decision prints but doesn't fail the process."""
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(
        decision_return={
            "decision": "block",
            "blockers": [],
            "rationale": "blocked",
        }
    )
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["decide", "--org", "example-org", "--repo", "example-org/svc"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Heuristic fallback source tag
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.decide.AegisClient")
@patch("aegis_cli.commands.decide.load_config")
def test_decide_local_source_shown_in_output(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(
        decision_return={
            "decision": "allow",
            "blockers": [],
            "rationale": "no findings",
            "source": "local",
        }
    )
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["decide", "--org", "example-org", "--repo", "example-org/svc"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "local" in result.output.lower()


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.decide.AegisClient")
@patch("aegis_cli.commands.decide.load_config")
def test_decide_json_output(mock_cfg, mock_client_cls):
    payload = {"decision": "allow", "blockers": [], "rationale": "clean"}
    mock_cfg.return_value = _make_cfg()
    mock_client_cls.return_value = _make_client(decision_return=payload)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["decide", "--org", "example-org", "--json"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["decision"] == "allow"


# ---------------------------------------------------------------------------
# Guard rails
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.decide.load_config")
def test_decide_exits_1_when_no_org(mock_cfg):
    mock_cfg.return_value = _make_cfg(org=None)
    runner = CliRunner()
    result = runner.invoke(cli, ["decide"], catch_exceptions=False)
    assert result.exit_code == 1


@patch("aegis_cli.commands.decide.AegisClient")
@patch("aegis_cli.commands.decide.load_config")
def test_decide_passes_block_on_to_client(mock_cfg, mock_client_cls):
    mock_cfg.return_value = _make_cfg()
    client_inst = _make_client(
        decision_return={"decision": "allow", "blockers": [], "rationale": "ok"}
    )
    mock_client_cls.return_value = client_inst

    runner = CliRunner()
    runner.invoke(
        cli,
        ["decide", "--org", "example-org", "--block-on", "critical,high"],
        catch_exceptions=False,
    )

    call_kwargs = client_inst.get_decision.call_args.kwargs
    assert "critical" in call_kwargs.get("block_on", [])
    assert "high" in call_kwargs.get("block_on", [])


# ---------------------------------------------------------------------------
# Endpoint-first / 404 fallback — exercises the real client method against
# a mocked HTTP layer to make sure the CLI prefers the backend endpoint and
# only falls back to the local heuristic when the endpoint is missing.
# ---------------------------------------------------------------------------


@patch("aegis_cli.commands.decide.load_config")
def test_decide_uses_backend_endpoint_when_available(mock_cfg, monkeypatch):
    """When the endpoint returns 200 the CLI uses that result, not the heuristic."""
    import httpx
    from aegis_cli import client as client_module

    mock_cfg.return_value = _make_cfg()

    backend_payload = {
        "decision": "allow",
        "blockers": [],
        "rationale": "backend says ok",
        "source": "backend",
    }

    class _Transport(httpx.BaseTransport):
        def handle_request(self, request):
            if "/api/v1/decisions/go-no-go" in request.url.path:
                return httpx.Response(200, json=backend_payload)
            return httpx.Response(404, json={"detail": "not found"})

    real_init = client_module.AegisClient.__init__

    def _patched_init(self, base_url, api_token, timeout=30.0):
        real_init(self, base_url, api_token, timeout)
        self._http = httpx.Client(
            transport=_Transport(),
            headers={"Authorization": f"Bearer {api_token}"},
        )

    monkeypatch.setattr(client_module.AegisClient, "__init__", _patched_init)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["decide", "--org", "example-org", "--repo", "example-org/svc", "--json"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["decision"] == "allow"
    assert parsed["source"] == "backend"


@patch("aegis_cli.commands.decide.load_config")
def test_decide_falls_back_to_local_on_404(mock_cfg, monkeypatch):
    """When the endpoint returns 404 the CLI falls back to the local heuristic."""
    import httpx
    from aegis_cli import client as client_module

    mock_cfg.return_value = _make_cfg()

    class _Transport(httpx.BaseTransport):
        def handle_request(self, request):
            path = request.url.path
            if "/api/v1/decisions/go-no-go" in path:
                return httpx.Response(404, json={"detail": "not found"})
            if "/history" in path:
                return httpx.Response(200, json={"history": []})
            return httpx.Response(404, json={"detail": "not found"})

    real_init = client_module.AegisClient.__init__

    def _patched_init(self, base_url, api_token, timeout=30.0):
        real_init(self, base_url, api_token, timeout)
        self._http = httpx.Client(
            transport=_Transport(),
            headers={"Authorization": f"Bearer {api_token}"},
        )

    monkeypatch.setattr(client_module.AegisClient, "__init__", _patched_init)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["decide", "--org", "example-org", "--repo", "example-org/svc", "--json"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["source"] == "local"
    assert parsed["decision"] == "allow"
