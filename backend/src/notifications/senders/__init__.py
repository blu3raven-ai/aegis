"""Sender implementations for each destination type.

`BaseSender` and `SendResult` are re-exported from the kernel so external
callers can still import them from this package — `from src.notifications.senders
import BaseSender` keeps working.
"""
from __future__ import annotations

from src.connectors.base import BaseSender, SendResult
from src.notifications.senders.slack import SlackSender
from src.notifications.senders.webhook import GenericWebhookSender
from src.notifications.senders.email import EmailSender
from src.notifications.senders.jira import JiraSender
from src.notifications.senders.linear import LinearSender
from src.notifications.senders.github_issues import GitHubIssuesSender

__all__ = [
    "BaseSender",
    "SendResult",
    "SlackSender",
    "GenericWebhookSender",
    "EmailSender",
    "JiraSender",
    "LinearSender",
    "GitHubIssuesSender",
]
