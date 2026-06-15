"""Pin the contract of the six notification senders.

Each sender must: register under a stable id, expose the right metadata,
and return SendResult from send(payload, config)."""
from __future__ import annotations

import importlib

import pytest

from src.connectors.base import SendResult
from src.connectors.registry import _reset_registry, get_connector


@pytest.fixture(autouse=True)
def _ensure_senders_registered():
    """Guarantee the six senders are in the registry before each test.

    Other test modules (test_connectors_registry, test_connectors_catalog) call
    _reset_registry() in their teardown, which empties the global dict. Python
    won't re-execute module-level @register_connector decorators on a plain
    re-import (modules are cached in sys.modules), so we must reset + reload to
    force re-registration.
    """
    import src.notifications.senders.slack as _slack
    import src.notifications.senders.webhook as _webhook
    import src.notifications.senders.email as _email
    import src.notifications.senders.jira as _jira
    import src.notifications.senders.linear as _linear
    import src.notifications.senders.github_issues as _gh

    _reset_registry()
    for mod in (_slack, _webhook, _email, _jira, _linear, _gh):
        importlib.reload(mod)
    yield
    _reset_registry()


# ── Registration ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("connector_id,cls_name,icon", [
    ("slack", "SlackSender", "slack"),
    ("generic-webhook", "GenericWebhookSender", "webhook"),
    ("email", "EmailSender", "email"),
    ("jira", "JiraSender", "jira"),
    ("linear", "LinearSender", "linear"),
    ("github-issues", "GitHubIssuesSender", "github"),
])
def test_sender_registered_with_metadata(connector_id, cls_name, icon):
    registered = get_connector(connector_id)
    assert registered.__name__ == cls_name
    assert registered.kind == "sender"
    assert registered.category == "notification"
    assert registered.icon_slug == icon
    assert registered.href == "/notifications"


# ── Stub senders return success without external calls ─────────────────────

def test_jira_send_returns_success_without_network():
    from src.notifications.senders import jira as _jira
    result = _jira.JiraSender().send(
        {"finding_id": "F-123"},
        {"project_key": "AEGIS"},
    )
    assert isinstance(result, SendResult)
    assert result.success is True


def test_linear_send_returns_success_without_network():
    from src.notifications.senders import linear as _linear
    result = _linear.LinearSender().send(
        {"finding_id": "F-123"},
        {"team_id": "T-1"},
    )
    assert isinstance(result, SendResult)
    assert result.success is True


def test_github_issues_send_returns_success_without_network():
    from src.notifications.senders import github_issues as _gh
    result = _gh.GitHubIssuesSender().send(
        {"finding_id": "F-123"},
        {"repo": "acme-org/example"},
    )
    assert isinstance(result, SendResult)
    assert result.success is True


# ── Config validation paths ────────────────────────────────────────────────

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


# ── Email test() probes SMTP env ───────────────────────────────────────────

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
