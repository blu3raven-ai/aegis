"""Sender implementations for each destination type."""
from __future__ import annotations

from src.notifications.senders.base import BaseSender, SendResult
from src.notifications.senders.slack import SlackSender
from src.notifications.senders.webhook import GenericWebhookSender
from src.notifications.senders.email import EmailSender
from src.notifications.senders.jira import JiraSender
from src.notifications.senders.linear import LinearSender
from src.notifications.senders.github_issues import GitHubIssuesSender

__all__ = ["BaseSender", "SendResult", "SlackSender", "GenericWebhookSender", "EmailSender", "JiraSender", "LinearSender", "GitHubIssuesSender"]
