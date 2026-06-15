"""SMTP email sender.

Reads connection parameters from environment:
  SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASSWORD,
  SMTP_FROM (default "aegis-notifications@example.com")

If SMTP_HOST is not set the sender degrades gracefully — it logs the email
body and records the delivery as 'failed' so operators know something was
attempted.

Expects config = {"to_addresses": ["user@example.com", ...]}
Payload must include "subject" and "body" keys (set by formatter).
"""
from __future__ import annotations

import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from src.connectors.base import BaseSender, SendResult, TestResult
from src.connectors.registry import register_connector

logger = logging.getLogger(__name__)

_DEFAULT_FROM = "aegis-notifications@example.com"


def _smtp_configured() -> bool:
    return bool(os.environ.get("SMTP_HOST"))


@register_connector
class EmailSender(BaseSender):
    id = "email"
    name = "Email"
    category = "notification"
    description = "Send finding digests to an email distribution list"
    version = "v1.0"
    status = "stable"
    icon_slug = "email"
    href = "/notifications"

    def send(self, payload: dict[str, Any], config: dict[str, Any]) -> SendResult:
        to_addresses: list[str] = config.get("to_addresses") or []
        if not to_addresses:
            return SendResult(success=False, error="email config missing to_addresses")

        subject = payload.get("subject", "(no subject)")
        body = payload.get("body", "")

        if not _smtp_configured():
            logger.warning(
                "SMTP not configured — skipped email to %s | subject: %s | body: %.200s",
                to_addresses,
                subject,
                body,
            )
            return SendResult(success=False, error="SMTP not configured")

        host = os.environ["SMTP_HOST"]
        port = int(os.environ.get("SMTP_PORT", "587"))
        user = os.environ.get("SMTP_USER", "")
        password = os.environ.get("SMTP_PASSWORD", "")
        from_addr = os.environ.get("SMTP_FROM", _DEFAULT_FROM)

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = from_addr
            msg["To"] = ", ".join(to_addresses)
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(host, port, timeout=15) as smtp:
                smtp.ehlo()
                smtp.starttls()
                if user:
                    smtp.login(user, password)
                smtp.sendmail(from_addr, to_addresses, msg.as_string())

            return SendResult(success=True, response_code=250)
        except Exception as exc:
            logger.warning("EmailSender.send error: %s", exc)
            return SendResult(success=False, error=str(exc)[:500])

    def test(self) -> TestResult:
        """OK only when SMTP_HOST is configured. Without it, sends are stubbed."""
        if not os.environ.get("SMTP_HOST"):
            return TestResult(ok=False, message="SMTP_HOST is not configured")
        return TestResult(ok=True)
