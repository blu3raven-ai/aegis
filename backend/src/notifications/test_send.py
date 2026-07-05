"""Test-send payload builder and dispatch shared by the admin router.

Constructs a fixed, unmistakable test payload per channel type and routes it
through the same sender used for live deliveries. Kept separate from
``formatter.py`` because the formatter is shaped around real bus events; a
test send carries no event_id and should make clear it's a manual probe.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.connectors.base import BaseSender, SendResult
from src.notifications.senders.email import EmailSender
from src.notifications.senders.slack import SlackSender
from src.notifications.senders.webhook import GenericWebhookSender


_TEST_SUBJECT = "[Aegis] Test notification"

# Senders are constructed lazily per-call so module import does not trigger
# any sender-side initialisation (e.g. SMTP probing in EmailSender).
_SENDER_CLASSES: dict[str, type[BaseSender]] = {
    "slack": SlackSender,
    "webhook": GenericWebhookSender,
    "email": EmailSender,
}


def _test_summary(destination_type: str) -> str:
    return (
        f"This is a test notification from Aegis — your {destination_type} "
        f"destination is working correctly. Sent at "
        f"{datetime.now(timezone.utc).isoformat()}."
    )


def build_test_payload(
    destination_type: str,
    destination_name: str,
) -> dict[str, Any]:
    """Return a sender-ready payload for a manual test send.

    Shape matches what each sender expects:
      - slack:   {"text": str, "blocks": [...]}
      - webhook: a flat JSON envelope marked test=True
      - email:   {"subject": str, "body": str}
    """
    summary = _test_summary(destination_type)
    timestamp = datetime.now(timezone.utc).isoformat()

    if destination_type == "slack":
        return {
            "text": summary,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "Aegis test notification",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": summary},
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"destination: *{destination_name}* | test",
                        }
                    ],
                },
            ],
        }

    if destination_type == "webhook":
        return {
            "source": "aegis",
            "test": True,
            "event_type": "aegis.test_notification",
            "destination_name": destination_name,
            "timestamp_utc": timestamp,
            "summary": summary,
        }

    if destination_type == "email":
        body_lines = [
            summary,
            "",
            f"Destination: {destination_name}",
            f"Timestamp: {timestamp}",
        ]
        return {"subject": _TEST_SUBJECT, "body": "\n".join(body_lines)}

    raise ValueError(f"unsupported destination_type: {destination_type!r}")


def send_test_payload(
    destination_type: str,
    payload: dict[str, Any],
    config: dict[str, Any],
) -> SendResult:
    """Dispatch a test payload through the matching channel sender."""
    sender_cls = _SENDER_CLASSES.get(destination_type)
    if sender_cls is None:
        return SendResult(
            success=False,
            error=f"no sender registered for destination_type {destination_type!r}",
        )
    return sender_cls().send(payload, config)
