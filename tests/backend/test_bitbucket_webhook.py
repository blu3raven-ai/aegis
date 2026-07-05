"""Tests for integrations.bitbucket_webhook — signature, event routing."""
from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.integrations.bitbucket_webhook import router


# ── fixtures ──────────────────────────────────────────────────────────────────


def _make_client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


def _sig(body: bytes, secret: str = "bb-secret") -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _post(
    client,
    payload: dict,
    event_key: str = "repo:push",
    secret: str = "bb-secret",
    bad_sig: bool = False,
):
    body = json.dumps(payload).encode()
    sig = "sha256=deadbeef" if bad_sig else _sig(body, secret)
    return client.post(
        "/integrations/bitbucket/webhook",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Event-Key": event_key,
            "X-Hub-Signature": sig,
        },
    )


@pytest.fixture
def client():
    return _make_client()


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("BITBUCKET_WEBHOOK_SECRET", "bb-secret")


PUSH_PAYLOAD = {
    "repository": {"full_name": "acme-org/security-portal"},
    "push": {
        "changes": [
            {
                "new": {"name": "main", "target": {"hash": "def456"}},
                "old": {"target": {"hash": "abc123"}},
                "commits": [
                    {"hash": "def456", "author": {"raw": "Dev <dev@acme-org.example.com>"}},
                ],
            }
        ]
    },
}

PR_PAYLOAD = {
    "repository": {"full_name": "acme-org/security-portal"},
    "pullrequest": {
        "id": 10,
        "title": "Harden auth",
        "author": {"nickname": "dev-user"},
        "source": {"commit": {"hash": "head999"}},
        "destination": {"commit": {"hash": "base000"}},
    },
}


# ── signature ─────────────────────────────────────────────────────────────────


def test_invalid_signature_returns_401(client):
    resp = _post(client, PUSH_PAYLOAD, bad_sig=True)
    assert resp.status_code == 401


def test_missing_signature_header_returns_422(client):
    body = json.dumps(PUSH_PAYLOAD).encode()
    resp = client.post(
        "/integrations/bitbucket/webhook",
        content=body,
        headers={"Content-Type": "application/json", "X-Event-Key": "repo:push"},
    )
    assert resp.status_code == 422


# ── push event ────────────────────────────────────────────────────────────────


@patch("src.integrations.bitbucket_webhook.get_event_publisher")
def test_push_publishes_code_push_event(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, PUSH_PAYLOAD, event_key="repo:push")

    assert resp.status_code == 200
    assert resp.json()["status"] == "accepted"
    mock_pub.publish.assert_called_once()
    ev = mock_pub.publish.call_args[0][0]
    assert ev.event_type == "code.push"
    assert ev.org_id == "acme-org"
    assert ev.source_component == "integrations.bitbucket"


# ── PR events ─────────────────────────────────────────────────────────────────


@patch("src.integrations.bitbucket_webhook.get_event_publisher")
def test_pr_created_publishes_pr_opened_event(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, PR_PAYLOAD, event_key="pullrequest:created")

    assert resp.status_code == 200
    ev = mock_pub.publish.call_args[0][0]
    assert ev.event_type == "code.pr_opened"


@patch("src.integrations.bitbucket_webhook.get_event_publisher")
def test_pr_updated_publishes_pr_updated_event(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, PR_PAYLOAD, event_key="pullrequest:updated")

    assert resp.status_code == 200
    ev = mock_pub.publish.call_args[0][0]
    assert ev.event_type == "code.pr_updated"


# ── unknown events ────────────────────────────────────────────────────────────


@patch("src.integrations.bitbucket_webhook.get_event_publisher")
def test_unknown_event_key_ignored(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, {"repository": {"full_name": "acme-org/repo"}}, event_key="pullrequest:approved")

    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    mock_pub.publish.assert_not_called()
