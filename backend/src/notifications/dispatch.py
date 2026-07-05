"""Shared channel dispatch used by both the event router and the retry worker.

Centralising the sender map here means the initial send and every retry re-send
go through the exact same code path — in particular the webhook sender's SSRF
guard applies identically on re-send, with no bypass.
"""
from __future__ import annotations

from typing import Any

from src.connectors.base import SendResult


def send_to_destination(
    dest_type: str, payload: dict[str, Any], config: dict[str, Any] | None
) -> SendResult:
    """Send an already-formatted payload to a destination via its channel sender.

    Returns a failure ``SendResult`` for an unknown destination type rather than
    raising, so callers can record the outcome uniformly.
    """
    from src.notifications.senders.email import EmailSender
    from src.notifications.senders.slack import SlackSender
    from src.notifications.senders.webhook import GenericWebhookSender

    sender_classes = {
        "slack": SlackSender,
        "webhook": GenericWebhookSender,
        "email": EmailSender,
    }
    sender_cls = sender_classes.get(dest_type)
    if sender_cls is None:
        return SendResult(
            success=False, error=f"no sender for destination type {dest_type!r}"
        )
    return sender_cls().send(payload, config or {})
