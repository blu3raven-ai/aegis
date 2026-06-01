"""Tests for integrations.gitlab_webhook — token verification, event routing."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.integrations.gitlab_webhook import router


# ── fixtures ──────────────────────────────────────────────────────────────────


def _make_client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


def _post(client, payload: dict, event_header: str = "Push Hook", token: str = "gl-secret"):
    body = json.dumps(payload).encode()
    return client.post(
        "/integrations/gitlab/webhook",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Gitlab-Token": token,
            "X-Gitlab-Event": event_header,
        },
    )


@pytest.fixture
def client():
    return _make_client()


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("GITLAB_WEBHOOK_SECRET", "gl-secret")


PUSH_PAYLOAD = {
    "object_kind": "push",
    "ref": "refs/heads/main",
    "before": "aaa",
    "after": "bbb",
    "project": {"path_with_namespace": "acme-org/security-portal"},
    "commits": [{"id": "bbb", "author": {"email": "dev@acme-org.example.com"}}],
}

MR_PAYLOAD = {
    "object_kind": "merge_request",
    "user": {"username": "dev-user"},
    "project": {"path_with_namespace": "acme-org/security-portal"},
    "object_attributes": {
        "iid": 3,
        "title": "Fix injection",
        "state": "opened",
        "action": "open",
        "diff_refs": {"base_sha": "base000", "head_sha": "head111"},
    },
}


# ── signature ─────────────────────────────────────────────────────────────────


def test_invalid_token_returns_401(client):
    resp = _post(client, PUSH_PAYLOAD, token="wrong-token")
    assert resp.status_code == 401


def test_missing_token_header_returns_422(client):
    body = json.dumps(PUSH_PAYLOAD).encode()
    resp = client.post(
        "/integrations/gitlab/webhook",
        content=body,
        headers={"Content-Type": "application/json", "X-Gitlab-Event": "Push Hook"},
    )
    assert resp.status_code == 422


# ── push event ────────────────────────────────────────────────────────────────


@patch("src.integrations.gitlab_webhook.get_event_publisher")
def test_push_publishes_code_push_event(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, PUSH_PAYLOAD, event_header="Push Hook")

    assert resp.status_code == 200
    assert resp.json()["status"] == "accepted"
    mock_pub.publish.assert_called_once()
    ev = mock_pub.publish.call_args[0][0]
    assert ev.event_type == "code.push"
    assert ev.org_id == "acme-org"
    assert ev.source_component == "integrations.gitlab"


# ── merge request events ──────────────────────────────────────────────────────


@patch("src.integrations.gitlab_webhook.get_event_publisher")
def test_mr_opened_publishes_pr_opened_event(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    resp = _post(client, MR_PAYLOAD, event_header="Merge Request Hook")

    assert resp.status_code == 200
    ev = mock_pub.publish.call_args[0][0]
    assert ev.event_type == "code.pr_opened"


@patch("src.integrations.gitlab_webhook.get_event_publisher")
def test_mr_update_publishes_pr_updated_event(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    updated_payload = {
        **MR_PAYLOAD,
        "object_attributes": {**MR_PAYLOAD["object_attributes"], "action": "update", "state": "opened"},
    }
    resp = _post(client, updated_payload, event_header="Merge Request Hook")

    assert resp.status_code == 200
    ev = mock_pub.publish.call_args[0][0]
    assert ev.event_type == "code.pr_updated"


@patch("src.integrations.gitlab_webhook.get_event_publisher")
def test_mr_reopen_publishes_pr_opened_event(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    reopen_payload = {
        **MR_PAYLOAD,
        "object_attributes": {**MR_PAYLOAD["object_attributes"], "action": "reopen"},
    }
    resp = _post(client, reopen_payload, event_header="Merge Request Hook")

    assert resp.status_code == 200
    ev = mock_pub.publish.call_args[0][0]
    assert ev.event_type == "code.pr_opened"


# ── unknown events ────────────────────────────────────────────────────────────


@patch("src.integrations.gitlab_webhook.get_event_publisher")
def test_unknown_event_type_ignored(mock_factory, client):
    mock_pub = MagicMock()
    mock_factory.return_value = mock_pub

    payload = {"object_kind": "tag_push", "project": {"path_with_namespace": "acme-org/repo"}}
    resp = _post(client, payload, event_header="Tag Push Hook")

    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    mock_pub.publish.assert_not_called()
