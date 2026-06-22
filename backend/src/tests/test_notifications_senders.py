"""Pin the contract of the three real notification senders.

Each sender must: register under a stable id, expose the right metadata,
and return SendResult from send(payload, config)."""
from __future__ import annotations

import pytest

from src.connectors.registry import _reset_registry, get_connector


@pytest.fixture(autouse=True)
def _ensure_senders_registered(reset_and_reload_connectors):
    """Guarantee the three senders are in the registry before each test —
    other test modules call _reset_registry() in teardown, so we reset
    and reload here too. Shared helper lives in conftest.py."""
    reset_and_reload_connectors(
        "src.notifications.senders.slack",
        "src.notifications.senders.webhook",
        "src.notifications.senders.email",
    )
    yield
    _reset_registry()



@pytest.mark.parametrize("connector_id,cls_name,icon", [
    ("slack", "SlackSender", "slack"),
    ("generic-webhook", "GenericWebhookSender", "webhook"),
    ("email", "EmailSender", "email"),
])
def test_sender_registered_with_metadata(connector_id, cls_name, icon):
    registered = get_connector(connector_id)
    assert registered.__name__ == cls_name
    assert registered.kind == "sender"
    assert registered.category == "notification"
    assert registered.icon_slug == icon
    assert registered.href == "/notifications"



def test_slack_send_missing_webhook_url_fails_with_message():
    from src.notifications.senders import slack as _slack
    result = _slack.SlackSender().send({"text": "hi"}, {})
    assert result.success is False
    assert "webhook_url" in (result.error or "")


def test_webhook_send_missing_url_fails_with_message():
    from src.notifications.senders import webhook as _webhook
    result = _webhook.GenericWebhookSender().send({"text": "hi"}, {})
    assert result.success is False
    assert "url" in (result.error or "")


def test_email_send_missing_to_addresses_fails_with_message():
    from src.notifications.senders import email as _email
    result = _email.EmailSender().send({"subject": "s", "body": "b"}, {})
    assert result.success is False
    assert "to_addresses" in (result.error or "")



def test_email_test_method_reports_smtp_missing(monkeypatch):
    from src.notifications.senders import email as _email
    monkeypatch.delenv("SMTP_HOST", raising=False)
    result = _email.EmailSender().test()
    assert result.ok is False
    assert "SMTP_HOST" in (result.message or "")


def test_email_test_method_reports_ok_when_smtp_configured(monkeypatch):
    from src.notifications.senders import email as _email
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    result = _email.EmailSender().test()
    assert result.ok is True




class _FakeResp:
    """Minimal httpx-style response stub for sender send-path tests."""
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class _FakeClientCtx:
    """Context manager that yields a fake httpx client capturing post calls."""
    def __init__(self, resp: _FakeResp, raises: Exception | None = None):
        self.resp = resp
        self.raises = raises
        self.calls: list[dict] = []

    def __enter__(self):
        outer = self

        class _Client:
            def post(self, url, *, json=None, content=None, headers=None):
                outer.calls.append({
                    "url": url, "json": json, "content": content, "headers": headers,
                })
                if outer.raises is not None:
                    raise outer.raises
                return outer.resp

        return _Client()

    def __exit__(self, *exc):
        return False



def test_slack_send_success_returns_success_result_with_200(monkeypatch):
    from src.notifications.senders import slack as _slack

    fake = _FakeClientCtx(_FakeResp(200, "ok"))
    monkeypatch.setattr(_slack, "default_client", lambda: fake)

    out = _slack.SlackSender().send(
        {"text": "hello"},
        {"webhook_url": "https://hooks.slack.test/x"},
    )
    assert out.success is True
    assert out.response_code == 200
    assert fake.calls[0]["url"] == "https://hooks.slack.test/x"
    assert fake.calls[0]["json"] == {"text": "hello"}


def test_slack_send_non_200_returns_failure_with_truncated_body(monkeypatch):
    from src.notifications.senders import slack as _slack

    long_body = "x" * 500
    fake = _FakeClientCtx(_FakeResp(429, long_body))
    monkeypatch.setattr(_slack, "default_client", lambda: fake)

    out = _slack.SlackSender().send(
        {"text": "hi"},
        {"webhook_url": "https://hooks.slack.test/x"},
    )
    assert out.success is False
    assert out.response_code == 429
    # Long body is truncated at 200 chars in the error message
    assert "429" in (out.error or "")
    assert len(out.error or "") <= 250


def test_slack_send_exception_returns_failure_with_truncated_error(monkeypatch):
    from src.notifications.senders import slack as _slack

    fake = _FakeClientCtx(_FakeResp(200), raises=RuntimeError("connection refused " + "x" * 1000))
    monkeypatch.setattr(_slack, "default_client", lambda: fake)

    out = _slack.SlackSender().send(
        {"text": "hi"}, {"webhook_url": "https://hooks.slack.test/x"},
    )
    assert out.success is False
    # Exception message is truncated at 500 chars
    assert (out.error or "").startswith("connection refused")
    assert len(out.error or "") <= 500



def test_webhook_send_success_returns_success_result_with_2xx(monkeypatch):
    from src.notifications.senders import webhook as _webhook

    fake = _FakeClientCtx(_FakeResp(202, "accepted"))
    monkeypatch.setattr(_webhook, "default_client", lambda: fake)

    out = _webhook.GenericWebhookSender().send(
        {"k": "v"},
        {"url": "https://example.test/hook"},
    )
    assert out.success is True
    assert out.response_code == 202
    sent = fake.calls[0]
    assert sent["url"] == "https://example.test/hook"
    # Body is JSON-encoded bytes
    assert sent["content"] == b'{"k": "v"}'
    assert sent["headers"]["Content-Type"] == "application/json"


def test_webhook_send_3xx_treated_as_failure(monkeypatch):
    # 2xx is success; anything outside that range must be reported as failure
    # so a misrouted 302 doesn't silently look "delivered".
    from src.notifications.senders import webhook as _webhook

    fake = _FakeClientCtx(_FakeResp(302, "redirect"))
    monkeypatch.setattr(_webhook, "default_client", lambda: fake)

    out = _webhook.GenericWebhookSender().send(
        {"k": "v"}, {"url": "https://example.test/hook"},
    )
    assert out.success is False
    assert out.response_code == 302


def test_webhook_send_legacy_secret_signs_with_sha256_header(monkeypatch):
    # Legacy `secret` field must still produce the pre-Phase-44 sha256= header
    # so existing receivers continue to verify successfully.
    from src.notifications.senders import webhook as _webhook

    fake = _FakeClientCtx(_FakeResp(200))
    monkeypatch.setattr(_webhook, "default_client", lambda: fake)

    out = _webhook.GenericWebhookSender().send(
        {"k": "v"},
        {"url": "https://example.test/hook", "secret": "shh"},
    )
    assert out.success is True
    sig_header = fake.calls[0]["headers"]["X-Aegis-Signature"]
    assert sig_header.startswith("sha256=")
    # Signature must verify against the actual body that was sent.
    body = fake.calls[0]["content"]
    import hashlib, hmac
    expected = "sha256=" + hmac.new(b"shh", body, hashlib.sha256).hexdigest()
    assert sig_header == expected


def test_webhook_send_phase44_active_signing_secret_uses_versioned_headers(monkeypatch):
    # When `_signing_secrets` has at least one active entry, the sender must
    # use the new versioned X-Aegis-* headers and skip the legacy sha256=
    # header (build_signing_headers owns the schema).
    from src.notifications.senders import webhook as _webhook

    fake = _FakeClientCtx(_FakeResp(200))
    monkeypatch.setattr(_webhook, "default_client", lambda: fake)

    out = _webhook.GenericWebhookSender().send(
        {"k": "v"},
        {
            "url": "https://example.test/hook",
            "_signing_secrets": [{"raw": "active-secret", "status": "active"}],
        },
    )
    assert out.success is True
    headers = fake.calls[0]["headers"]
    assert "X-Aegis-Signature-Version" in headers
    assert "X-Aegis-Timestamp" in headers
    assert "X-Aegis-Signature" in headers
    # The Phase 44 versioned signature is v1=<hex>, not sha256=<hex>
    assert headers["X-Aegis-Signature"].startswith("v1=")


def test_webhook_send_revoked_signing_secrets_ignored(monkeypatch):
    # A channel mid-rotation with only revoked entries must fall back to the
    # legacy code path (legacy secret if present, else no signing headers) —
    # otherwise rotation would silently break the receiver.
    from src.notifications.senders import webhook as _webhook

    fake = _FakeClientCtx(_FakeResp(200))
    monkeypatch.setattr(_webhook, "default_client", lambda: fake)

    out = _webhook.GenericWebhookSender().send(
        {"k": "v"},
        {
            "url": "https://example.test/hook",
            "_signing_secrets": [
                {"raw": "old", "status": "revoked"},
                # Missing raw is also ignored
                {"status": "active"},
            ],
        },
    )
    assert out.success is True
    headers = fake.calls[0]["headers"]
    assert "X-Aegis-Signature-Version" not in headers
    # No legacy secret either → no sig header at all
    assert "X-Aegis-Signature" not in headers


def test_webhook_send_exception_returns_failure_result(monkeypatch):
    from src.notifications.senders import webhook as _webhook

    fake = _FakeClientCtx(_FakeResp(200), raises=ConnectionError("dns fail"))
    monkeypatch.setattr(_webhook, "default_client", lambda: fake)

    out = _webhook.GenericWebhookSender().send(
        {"k": "v"}, {"url": "https://example.test/hook"},
    )
    assert out.success is False
    assert (out.error or "").startswith("dns fail")



def test_email_send_smtp_unconfigured_returns_failure_with_clear_message(monkeypatch):
    # When SMTP_HOST is missing, send must not raise — it logs and reports a
    # failed delivery so the audit row makes it obvious why nothing went out.
    from src.notifications.senders import email as _email

    monkeypatch.delenv("SMTP_HOST", raising=False)
    out = _email.EmailSender().send(
        {"subject": "s", "body": "b"},
        {"to_addresses": ["alice@example.test"]},
    )
    assert out.success is False
    assert "SMTP not configured" in (out.error or "")


def test_email_send_success_path_calls_smtp_sendmail(monkeypatch):
    # Full SMTP success: confirm sendmail() gets called with the right args
    # and the result reports response_code=250 (SMTP "OK" code).
    from src.notifications.senders import email as _email

    monkeypatch.setenv("SMTP_HOST", "smtp.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USER", "u")
    monkeypatch.setenv("SMTP_PASSWORD", "p")
    monkeypatch.setenv("SMTP_FROM", "ops@example.test")

    sendmail_calls: list[tuple] = []

    class _FakeSMTP:
        def __init__(self, host, port, timeout=15):
            self.host = host
            self.port = port

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def ehlo(self):
            pass

        def starttls(self):
            pass

        def login(self, user, pw):
            pass

        def sendmail(self, frm, to, msg):
            sendmail_calls.append((frm, tuple(to), msg))

    monkeypatch.setattr(_email.smtplib, "SMTP", _FakeSMTP)

    out = _email.EmailSender().send(
        {"subject": "hello", "body": "world"},
        {"to_addresses": ["alice@example.test", "bob@example.test"]},
    )
    assert out.success is True
    assert out.response_code == 250
    assert len(sendmail_calls) == 1
    frm, to, msg = sendmail_calls[0]
    assert frm == "ops@example.test"
    assert to == ("alice@example.test", "bob@example.test")
    # MIME message must include subject and body
    assert "Subject: hello" in msg
    assert "world" in msg


def test_email_send_smtp_exception_returns_failure_with_truncated_error(monkeypatch):
    from src.notifications.senders import email as _email

    monkeypatch.setenv("SMTP_HOST", "smtp.test")

    class _BoomSMTP:
        def __init__(self, *a, **kw):
            raise RuntimeError("connection refused " + "x" * 1000)

    monkeypatch.setattr(_email.smtplib, "SMTP", _BoomSMTP)

    out = _email.EmailSender().send(
        {"subject": "s", "body": "b"},
        {"to_addresses": ["alice@example.test"]},
    )
    assert out.success is False
    assert (out.error or "").startswith("connection refused")
    assert len(out.error or "") <= 500
