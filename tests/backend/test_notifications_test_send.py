"""Tests for POST /api/v1/notifications/destinations/{dest_id}/test.

Uses the same minimal FastAPI harness as test_notification_admin_router.py —
real DB CRUD, mocked external I/O on the senders.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import delete

from src.db.helpers import run_db
from src.db.models import NotificationDelivery, NotificationDestination
from src.notifications.admin_router import router as notifications_admin_router
from src.notifications.senders.base import SendResult
from src.notifications.test_send import build_test_payload

ORG = "acme-org"
OTHER_ORG = "other-org"


def _require_permission_noop(request: Request, permission: str) -> None:
    pass


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(delete(NotificationDelivery))
        await session.execute(delete(NotificationDestination))
    run_db(_del)
    yield


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(
        "src.notifications.admin_router.require_permission",
        _require_permission_noop,
    )
    mini = FastAPI()
    mini.include_router(notifications_admin_router)
    return TestClient(mini, raise_server_exceptions=True)


def _create_slack(client, *, org=ORG, name="slack-test"):
    resp = client.post(
        "/api/v1/notifications/destinations",
        json={
            "org_id": org,
            "destination_type": "slack",
            "name": name,
            "config": {"webhook_url": "https://hooks.example.org/test"},
        },
    )
    assert resp.status_code == 201
    return resp.json()["id"]


def _create_webhook(client, *, org=ORG, name="wh-test", secret=None):
    config = {"url": "https://hooks.example.org/wh"}
    if secret:
        config["secret"] = secret
    resp = client.post(
        "/api/v1/notifications/destinations",
        json={
            "org_id": org,
            "destination_type": "webhook",
            "name": name,
            "config": config,
        },
    )
    assert resp.status_code == 201
    return resp.json()["id"]


def _create_email(client, *, org=ORG, name="email-test"):
    resp = client.post(
        "/api/v1/notifications/destinations",
        json={
            "org_id": org,
            "destination_type": "email",
            "name": name,
            "config": {"to_addresses": ["sec@example.com"]},
        },
    )
    assert resp.status_code == 201
    return resp.json()["id"]


# ── Success per channel ──────────────────────────────────────────────────────


def test_slack_test_send_success(client):
    dest_id = _create_slack(client)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("src.notifications.senders.slack.httpx.post", return_value=mock_resp) as mock_post:
        resp = client.post(f"/api/v1/notifications/destinations/{dest_id}/test?org_id={ORG}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "delivered"
    assert body["channel"] == "slack"
    assert isinstance(body["latency_ms"], int)
    assert body["latency_ms"] >= 0

    # Verify the payload sent to Slack contains the unmistakable test summary
    sent_payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
    assert "test notification from Aegis" in sent_payload["text"]


def test_webhook_test_send_success(client):
    dest_id = _create_webhook(client, secret="abc")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("src.notifications.senders.webhook.httpx.post", return_value=mock_resp) as mock_post:
        resp = client.post(f"/api/v1/notifications/destinations/{dest_id}/test?org_id={ORG}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "delivered"
    assert body["channel"] == "webhook"

    # Test payload should mark itself
    sent_body = mock_post.call_args.kwargs.get("content") or mock_post.call_args[1].get("content")
    assert b'"test": true' in sent_body or b'"test":true' in sent_body


def test_email_test_send_success(client, monkeypatch):
    dest_id = _create_email(client)
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "587")

    mock_smtp = MagicMock()
    mock_smtp.__enter__ = lambda s: s
    mock_smtp.__exit__ = MagicMock(return_value=False)
    with patch("src.notifications.senders.email.smtplib.SMTP", return_value=mock_smtp):
        resp = client.post(f"/api/v1/notifications/destinations/{dest_id}/test?org_id={ORG}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "delivered"
    assert body["channel"] == "email"


# ── Failure case (channel rejects) ──────────────────────────────────────────


def test_slack_test_send_failure_returns_200_with_error(client):
    dest_id = _create_slack(client)
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "forbidden"
    with patch("src.notifications.senders.slack.httpx.post", return_value=mock_resp):
        resp = client.post(f"/api/v1/notifications/destinations/{dest_id}/test?org_id={ORG}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "failed"
    assert body["channel"] == "slack"
    assert "403" in body["error"]
    assert "latency_ms" in body


def test_webhook_test_send_network_error_returns_200(client):
    dest_id = _create_webhook(client)
    with patch(
        "src.notifications.senders.webhook.httpx.post",
        side_effect=ConnectionError("refused"),
    ):
        resp = client.post(f"/api/v1/notifications/destinations/{dest_id}/test?org_id={ORG}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "failed"
    assert "refused" in body["error"]


def test_email_test_send_smtp_unconfigured_returns_failure(client, monkeypatch):
    dest_id = _create_email(client)
    monkeypatch.delenv("SMTP_HOST", raising=False)
    resp = client.post(f"/api/v1/notifications/destinations/{dest_id}/test?org_id={ORG}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "failed"
    assert "SMTP" in body["error"]


# ── Cross-org isolation ──────────────────────────────────────────────────────


def test_cross_org_destination_returns_404(client):
    dest_id = _create_slack(client, org=ORG)
    resp = client.post(
        f"/api/v1/notifications/destinations/{dest_id}/test?org_id={OTHER_ORG}"
    )
    assert resp.status_code == 404


def test_unknown_destination_returns_404(client):
    resp = client.post(
        f"/api/v1/notifications/destinations/99999/test?org_id={ORG}"
    )
    assert resp.status_code == 404


# ── Malformed input ──────────────────────────────────────────────────────────


def test_malformed_destination_id_returns_422(client):
    resp = client.post(
        f"/api/v1/notifications/destinations/not-a-number/test?org_id={ORG}"
    )
    assert resp.status_code == 422


def test_missing_org_id_returns_422(client):
    dest_id = _create_slack(client)
    resp = client.post(f"/api/v1/notifications/destinations/{dest_id}/test")
    assert resp.status_code == 422


def test_unsupported_channel_type_returns_422(client):
    # Simulate a destination row whose destination_type is outside the
    # canonical set (e.g. DB corruption or a channel type added without
    # updating test_send). The endpoint must fail loudly with 422.
    with patch(
        "src.notifications.admin_router.get_destination",
        return_value={
            "id": 1,
            "org_id": ORG,
            "destination_type": "unknown_future_type",
            "name": "ghost",
            "config": {},
        },
    ):
        resp = client.post(
            f"/api/v1/notifications/destinations/1/test?org_id={ORG}"
        )
    assert resp.status_code == 422
    assert "unknown_future_type" in resp.json()["detail"]


# ── Payload builder ──────────────────────────────────────────────────────────


def test_build_test_payload_slack_shape():
    payload = build_test_payload("slack", "my-slack", "acme-org")
    assert "text" in payload
    assert "blocks" in payload
    assert "test notification from Aegis" in payload["text"]
    assert "slack" in payload["text"]


def test_build_test_payload_webhook_marks_test():
    payload = build_test_payload("webhook", "my-wh", "acme-org")
    assert payload["test"] is True
    assert payload["event_type"] == "aegis.test_notification"
    assert payload["org_id"] == "acme-org"


def test_build_test_payload_email_shape():
    payload = build_test_payload("email", "my-email", "acme-org")
    assert payload["subject"].startswith("[Aegis]")
    assert "test notification from Aegis" in payload["body"]


def test_build_test_payload_unknown_type_raises():
    with pytest.raises(ValueError):
        build_test_payload("fax", "anything", "acme-org")


# ── No delivery record is persisted for test sends ──────────────────────────


def test_test_send_does_not_pollute_deliveries_table(client):
    dest_id = _create_slack(client)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("src.notifications.senders.slack.httpx.post", return_value=mock_resp):
        resp = client.post(f"/api/v1/notifications/destinations/{dest_id}/test?org_id={ORG}")
    assert resp.status_code == 200

    deliv_resp = client.get(
        f"/api/v1/notifications/destinations/{dest_id}/deliveries?org_id={ORG}"
    )
    assert deliv_resp.status_code == 200
    assert deliv_resp.json()["deliveries"] == []


# ── Per-destination isolation: two slack channels are independent ──────────


def test_per_destination_isolation(client):
    dest_a = _create_slack(client, name="slack-a")
    dest_b = _create_slack(client, name="slack-b")

    mock_ok = MagicMock(); mock_ok.status_code = 200
    mock_fail = MagicMock(); mock_fail.status_code = 500; mock_fail.text = "boom"

    # First call: a succeeds, b fails
    with patch(
        "src.notifications.senders.slack.httpx.post",
        side_effect=[mock_ok, mock_fail],
    ):
        resp_a = client.post(f"/api/v1/notifications/destinations/{dest_a}/test?org_id={ORG}")
        resp_b = client.post(f"/api/v1/notifications/destinations/{dest_b}/test?org_id={ORG}")

    assert resp_a.json()["status"] == "delivered"
    assert resp_b.json()["status"] == "failed"
