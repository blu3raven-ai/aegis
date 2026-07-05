"""Tests for Slack, generic webhook, and email senders.

All external I/O (httpx, SMTP) is mocked so no network calls are made.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from unittest.mock import MagicMock, patch

import pytest

from src.notifications.senders.email import EmailSender
from src.notifications.senders.slack import SlackSender
from src.notifications.senders.webhook import GenericWebhookSender, _sign


# ── SlackSender ───────────────────────────────────────────────────────────────


class TestSlackSender:
    def _payload(self):
        return {"text": "test alert", "blocks": []}

    def test_success_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("src.notifications.senders.slack.httpx.post", return_value=mock_resp) as mock_post:
            result = SlackSender().send(self._payload(), {"webhook_url": "https://hooks.example.org/x"})
        assert result.success is True
        assert result.response_code == 200
        mock_post.assert_called_once()

    def test_non_200_returns_failure(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "forbidden"
        with patch("src.notifications.senders.slack.httpx.post", return_value=mock_resp):
            result = SlackSender().send(self._payload(), {"webhook_url": "https://hooks.example.org/x"})
        assert result.success is False
        assert result.response_code == 403

    def test_network_exception_returns_failure(self):
        with patch("src.notifications.senders.slack.httpx.post", side_effect=ConnectionError("refused")):
            result = SlackSender().send(self._payload(), {"webhook_url": "https://hooks.example.org/x"})
        assert result.success is False
        assert "refused" in (result.error or "")

    def test_missing_webhook_url_returns_failure(self):
        result = SlackSender().send(self._payload(), {})
        assert result.success is False
        assert "webhook_url" in (result.error or "")


# ── GenericWebhookSender ──────────────────────────────────────────────────────


class TestGenericWebhookSender:
    def _payload(self):
        return {"event_type": "chain.created", "org_id": "acme-org"}

    def test_success_includes_signature_header(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        config = {"url": "https://hooks.example.org/wh", "secret": "my-secret"}
        with patch("src.notifications.senders.webhook.httpx.post", return_value=mock_resp) as mock_post:
            result = GenericWebhookSender().send(self._payload(), config)
        assert result.success is True
        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert "X-Aegis-Signature" in headers
        assert headers["X-Aegis-Signature"].startswith("sha256=")

    def test_signature_verifiable(self):
        payload = {"event_type": "finding.created"}
        secret = "verify-secret"
        body = json.dumps(payload, default=str).encode()
        sig = _sign(body, secret)
        mac = hmac.new(secret.encode(), body, hashlib.sha256)
        assert sig == f"sha256={mac.hexdigest()}"

    def test_no_secret_omits_signature_header(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        config = {"url": "https://hooks.example.org/no-secret"}
        with patch("src.notifications.senders.webhook.httpx.post", return_value=mock_resp) as mock_post:
            result = GenericWebhookSender().send(self._payload(), config)
        assert result.success is True
        headers = mock_post.call_args.kwargs.get("headers", {})
        assert "X-Aegis-Signature" not in headers

    def test_4xx_returns_failure(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "not found"
        with patch("src.notifications.senders.webhook.httpx.post", return_value=mock_resp):
            result = GenericWebhookSender().send(self._payload(), {"url": "https://hooks.example.org/wh"})
        assert result.success is False
        assert result.response_code == 404

    def test_missing_url_returns_failure(self):
        result = GenericWebhookSender().send(self._payload(), {})
        assert result.success is False
        assert "url" in (result.error or "")


# ── EmailSender ───────────────────────────────────────────────────────────────


class TestEmailSender:
    def _payload(self):
        return {"subject": "Aegis alert", "body": "Critical finding detected."}

    def test_no_smtp_host_returns_failure(self, monkeypatch):
        monkeypatch.delenv("SMTP_HOST", raising=False)
        result = EmailSender().send(self._payload(), {"to_addresses": ["sec@example.com"]})
        assert result.success is False
        assert "SMTP" in (result.error or "")

    def test_missing_to_addresses_returns_failure(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        result = EmailSender().send(self._payload(), {})
        assert result.success is False
        assert "to_addresses" in (result.error or "")

    def test_smtp_send_success(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_PORT", "587")
        monkeypatch.setenv("SMTP_USER", "user@example.com")
        monkeypatch.setenv("SMTP_PASSWORD", "password")

        mock_smtp = MagicMock()
        mock_smtp.__enter__ = lambda s: s
        mock_smtp.__exit__ = MagicMock(return_value=False)

        with patch("src.notifications.senders.email.smtplib.SMTP", return_value=mock_smtp):
            result = EmailSender().send(self._payload(), {"to_addresses": ["sec@example.com"]})

        assert result.success is True
        assert result.response_code == 250

    def test_smtp_exception_returns_failure(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        import smtplib
        with patch("src.notifications.senders.email.smtplib.SMTP", side_effect=smtplib.SMTPConnectError(421, "unavailable")):
            result = EmailSender().send(self._payload(), {"to_addresses": ["sec@example.com"]})
        assert result.success is False
        assert result.error is not None
