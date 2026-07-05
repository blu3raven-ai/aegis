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
from src.notifications.url_guard import UnsafeURLError, assert_sendable_url

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
            assert_sendable_url(url)
        except UnsafeURLError:
            return SendResult(success=False, error="blocked: destination URL is not permitted")

        try:
            with default_client() as client:
                resp = client.post(url, json=payload)
            if resp.status_code == 200:
                return SendResult(success=True, response_code=resp.status_code)
            # Record only the status code — never the response body, which an
            # attacker-controlled internal endpoint could use as an exfil oracle.
            return SendResult(
                success=False,
                response_code=resp.status_code,
                error=f"slack returned status {resp.status_code}",
            )
        except Exception as exc:
            logger.warning("SlackSender.send error: %s", exc)
            return SendResult(success=False, error=str(exc)[:500])

    def test(self) -> TestResult:
        """The destination webhook URL lives in per-destination config, which
        this no-config capability check never receives, so there is nothing to
        probe at this layer. Report available but self-report the absence of a
        liveness probe so an ops surface doesn't read this as "verified
        reachable" — Slack delivery is exercised per-destination at send time."""
        return TestResult(
            ok=True,
            message="No liveness probe — Slack delivery is verified per-destination at send time",
        )
