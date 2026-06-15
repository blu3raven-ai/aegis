"""Slack Incoming Webhook sender.

Expects config = {"webhook_url": "https://hooks.slack.com/..."}
Payload must be a dict with a top-level "blocks" list (Slack Block Kit) or
a plain "text" key. The formatter produces Block Kit payloads.
"""
from __future__ import annotations

import logging
from typing import Any

from src.connectors.base import BaseSender, SendResult, TestResult
from src.connectors.http import default_client
from src.connectors.registry import register_connector

logger = logging.getLogger(__name__)


@register_connector
class SlackSender(BaseSender):
    id = "slack"
    name = "Slack"
    category = "notification"
    description = "Post findings to a Slack channel via Incoming Webhooks"
    version = "v1.0"
    status = "stable"
    icon_slug = "slack"
    href = "/notifications"

    def send(self, payload: dict[str, Any], config: dict[str, Any]) -> SendResult:
        url = config.get("webhook_url", "")
        if not url:
            return SendResult(success=False, error="slack config missing webhook_url")

        try:
            with default_client() as client:
                resp = client.post(url, json=payload)
            if resp.status_code == 200:
                return SendResult(success=True, response_code=resp.status_code)
            return SendResult(
                success=False,
                response_code=resp.status_code,
                error=f"slack returned {resp.status_code}: {resp.text[:200]}",
            )
        except Exception as exc:
            logger.warning("SlackSender.send error: %s", exc)
            return SendResult(success=False, error=str(exc)[:500])

    def test(self) -> TestResult:
        """No external probe — registration-time liveness check only."""
        return TestResult(ok=True)
