"""Slack Incoming Webhook sender.

Expects config = {"webhook_url": "https://hooks.slack.com/..."}
Payload must be a dict with a top-level "blocks" list (Slack Block Kit) or
a plain "text" key. The formatter produces Block Kit payloads.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from src.notifications.senders.base import BaseSender, SendResult

logger = logging.getLogger(__name__)

_TIMEOUT_S = 10


class SlackSender(BaseSender):
    def send(self, payload: dict[str, Any], config: dict[str, Any]) -> SendResult:
        url = config.get("webhook_url", "")
        if not url:
            return SendResult(success=False, error="slack config missing webhook_url")

        try:
            resp = httpx.post(url, json=payload, timeout=_TIMEOUT_S)
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
