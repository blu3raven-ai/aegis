"""Tests for integrations.github_webhook — signature, routing, event publishing."""
from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.integrations.github_webhook import router


# ── fixtures ──────────────────────────────────────────────────────────────────


def _make_client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


def _sig(body: bytes, secret: str = "gh-secret") -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _post(client, payload: dict, event: str = "push", secret: str = "gh-secret", bad_sig: bool = False):
    body = json.dumps(payload).encode()
    sig = "sha256=deadbeef" if bad_sig else _sig(body, secret)
    return client.post(
        "/integrations/github/webhook",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": event,
            "X-Hub-Signature-256": sig,
        },
    )


@pytest.fixture
def client():
    return _make_client()


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh-secret")


PUSH_PAYLOAD = {
    "ref": "refs/heads/main",
    "before": "abc",
    "after": "def",
    "repository": {"name": "repo", "owner": {"login": "acme-org"}},
    "commits": [{"id": "def", "author": {"email": "dev@acme-org.example.com"}}],
}

PR_PAYLOAD = {
    "action": "opened",
    "repository": {"name": "repo", "owner": {"login": "acme-org"}},
    "pull_request": {
        "number": 1,
        "title": "feat",
        "user": {"login": "dev-user"},
        "base": {"sha": "base"},
        "head": {"sha": "head"},
    },
}


# ── signature ─────────────────────────────────────────────────────────────────


def test_invalid_signature_returns_401(client):
    resp = _post(client, PUSH_PAYLOAD, bad_sig=True)
    assert resp.status_code == 401


def test_missing_signature_header_returns_422(client):
    body = json.dumps(PUSH_PAYLOAD).encode()
    resp = client.post(
        "/integrations/github/webhook",
        content=body,
        headers={"Content-Type": "application/json", "X-GitHub-Event": "push"},
    )
    # FastAPI returns 422 for missing required header
    assert resp.status_code == 422


# ── push event ────────────────────────────────────────────────────────────────


@patch("src.integrations.github_webhook.get_event_publisher")
def test_push_publishes_code_push_event(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, PUSH_PAYLOAD, event="push")

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "accepted"
    assert "event_id" in data
    mock_pub.publish.assert_called_once()
    ev = mock_pub.publish.call_args[0][0]
    assert ev.event_type == "code.push"
    assert ev.org_id == "acme-org"
    assert ev.source_component == "integrations.github"


# ── pull_request events ───────────────────────────────────────────────────────


@patch("src.integrations.github_webhook.get_event_publisher")
def test_pr_opened_publishes_pr_opened_event(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, {**PR_PAYLOAD, "action": "opened"}, event="pull_request")

    assert resp.status_code == 200
    ev = mock_pub.publish.call_args[0][0]
    assert ev.event_type == "code.pr_opened"


@patch("src.integrations.github_webhook.get_event_publisher")
def test_pr_reopened_publishes_pr_opened_event(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, {**PR_PAYLOAD, "action": "reopened"}, event="pull_request")

    assert resp.status_code == 200
    ev = mock_pub.publish.call_args[0][0]
    assert ev.event_type == "code.pr_opened"


@patch("src.integrations.github_webhook.get_event_publisher")
def test_pr_synchronize_publishes_pr_updated_event(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, {**PR_PAYLOAD, "action": "synchronize"}, event="pull_request")

    assert resp.status_code == 200
    ev = mock_pub.publish.call_args[0][0]
    assert ev.event_type == "code.pr_updated"


@patch("src.integrations.github_webhook.get_event_publisher")
def test_pr_edited_publishes_pr_updated_event(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, {**PR_PAYLOAD, "action": "edited"}, event="pull_request")

    assert resp.status_code == 200
    ev = mock_pub.publish.call_args[0][0]
    assert ev.event_type == "code.pr_updated"


@patch("src.integrations.github_webhook.get_event_publisher")
def test_pr_closed_is_ignored(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, {**PR_PAYLOAD, "action": "closed"}, event="pull_request")

    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    mock_pub.publish.assert_not_called()


# ── ping event ────────────────────────────────────────────────────────────────


@patch("src.integrations.github_webhook.get_event_publisher")
def test_ping_returns_pong(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, {"zen": "Non-blocking is better than blocking."}, event="ping")

    assert resp.status_code == 200
    assert resp.json()["status"] == "pong"
    mock_pub.publish.assert_not_called()


# ── unknown events ────────────────────────────────────────────────────────────


@patch("src.integrations.github_webhook.get_event_publisher")
def test_unknown_event_type_ignored(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, {"foo": "bar"}, event="deployment")

    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    mock_pub.publish.assert_not_called()
