"""Tests for argus.webhook — signature verification and intel event publishing."""
from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.argus.webhook import router, verify_signature


# ── verify_signature ──────────────────────────────────────────────────────────


def _make_sig(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_verify_signature_valid():
    secret = "test-webhook-secret"
    body = b'{"event_type":"cve_published"}'
    sig = _make_sig(body, secret)
    assert verify_signature(body, sig, secret) is True


def test_verify_signature_invalid():
    body = b'{"event_type":"cve_published"}'
    sig = "sha256=deadbeef"
    assert verify_signature(body, sig, "correct-secret") is False


def test_verify_signature_missing_signature():
    body = b'{"event_type":"cve_published"}'
    assert verify_signature(body, "", "correct-secret") is False


def test_verify_signature_empty_secret():
    body = b'{"event_type":"cve_published"}'
    sig = _make_sig(body, "any-secret")
    assert verify_signature(body, sig, "") is False


def test_verify_signature_none_signature():
    body = b'{"event_type":"cve_published"}'
    assert verify_signature(body, None, "correct-secret") is False


# ── webhook endpoint ──────────────────────────────────────────────────────────


def _make_client() -> TestClient:
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


def _post_webhook(client, payload: dict, secret: str = "webhook-secret", headers: dict | None = None):
    body = json.dumps(payload).encode()
    sig = _make_sig(body, secret)
    h = {"X-Argus-Signature": sig, "Content-Type": "application/json"}
    if headers:
        h.update(headers)
    return client.post("/argus/webhook", content=body, headers=h)


@pytest.fixture
def client():
    return _make_client()


@pytest.fixture(autouse=True)
def _set_secret(monkeypatch):
    monkeypatch.setenv("ARGUS_WEBHOOK_SECRET", "webhook-secret")


# ── signature rejection ───────────────────────────────────────────────────────


def test_missing_signature_returns_401(client):
    body = json.dumps({"event_type": "cve_published", "org_id": "acme-org", "data": {}}).encode()
    resp = client.post(
        "/argus/webhook",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 401


def test_invalid_signature_returns_401(client):
    body = json.dumps({"event_type": "cve_published", "org_id": "acme-org", "data": {}}).encode()
    resp = client.post(
        "/argus/webhook",
        content=body,
        headers={
            "X-Argus-Signature": "sha256=0000000000000000",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 401


# ── event publishing ──────────────────────────────────────────────────────────


@patch("src.argus.webhook.get_event_publisher")
def test_cve_published_event_published(mock_pub_factory, client):
    mock_pub = MagicMock()
    mock_pub_factory.return_value = mock_pub

    payload = {
        "event_type": "cve_published",
        "org_id": "acme-org",
        "data": {"cve_id": "CVE-2024-0001", "affected_package": "lodash"},
    }
    resp = _post_webhook(client, payload)

    assert resp.status_code == 200
    assert resp.json()["handled"] is True
    mock_pub.publish.assert_called_once()
    published_event = mock_pub.publish.call_args[0][0]
    assert published_event.event_type == "intel.cve_published"
    assert published_event.org_id == "acme-org"
    assert published_event.source_component == "argus.webhook"


@patch("src.argus.webhook.get_event_publisher")
def test_epss_changed_event_published(mock_pub_factory, client):
    mock_pub = MagicMock()
    mock_pub_factory.return_value = mock_pub

    payload = {
        "event_type": "epss_changed",
        "org_id": "acme-org",
        "data": {"cve_id": "CVE-2024-0002", "new_epss": 0.9, "old_epss": 0.3},
    }
    resp = _post_webhook(client, payload)

    assert resp.status_code == 200
    published_event = mock_pub.publish.call_args[0][0]
    assert published_event.event_type == "intel.epss_changed"


@patch("src.argus.webhook.get_event_publisher")
def test_exploit_availability_changed_published(mock_pub_factory, client):
    mock_pub = MagicMock()
    mock_pub_factory.return_value = mock_pub

    payload = {
        "event_type": "exploit_availability_changed",
        "org_id": "acme-org",
        "data": {"cve_id": "CVE-2024-0003", "exploit_status": "public_poc"},
    }
    resp = _post_webhook(client, payload)

    assert resp.status_code == 200
    published_event = mock_pub.publish.call_args[0][0]
    assert published_event.event_type == "intel.exploit_availability_changed"


@patch("src.argus.webhook.get_event_publisher")
def test_rule_pack_updated_published(mock_pub_factory, client):
    mock_pub = MagicMock()
    mock_pub_factory.return_value = mock_pub

    payload = {
        "event_type": "rule_pack_updated",
        "org_id": "acme-org",
        "data": {"version": "2026.05.31"},
    }
    resp = _post_webhook(client, payload)

    assert resp.status_code == 200
    published_event = mock_pub.publish.call_args[0][0]
    assert published_event.event_type == "intel.rule_pack_updated"


@patch("src.argus.webhook.get_event_publisher")
def test_unknown_event_type_acknowledged_not_published(mock_pub_factory, client):
    mock_pub = MagicMock()
    mock_pub_factory.return_value = mock_pub

    payload = {
        "event_type": "future_event_we_dont_know_yet",
        "org_id": "acme-org",
        "data": {},
    }
    resp = _post_webhook(client, payload)

    assert resp.status_code == 200
    assert resp.json()["handled"] is False
    mock_pub.publish.assert_not_called()


def test_malformed_json_returns_400(client, monkeypatch):
    secret = "webhook-secret"
    body = b"not-valid-json"
    sig = _make_sig(body, secret)
    resp = client.post(
        "/argus/webhook",
        content=body,
        headers={"X-Argus-Signature": sig, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400
