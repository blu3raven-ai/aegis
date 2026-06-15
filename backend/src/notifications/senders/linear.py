"""Linear sender stub — logs findings; real API integration is a future phase."""
from __future__ import annotations
import logging
from typing import Any

from src.connectors.base import BaseSender, SendResult, TestResult
from src.connectors.registry import register_connector

logger = logging.getLogger(__name__)


@register_connector
class LinearSender(BaseSender):
    id = "linear"
    name = "Linear"
    category = "notification"
    description = "Create Linear issues for new findings (stub)"
    version = "v0.5"
    status = "beta"
    icon_slug = "linear"
    href = "/notifications"

    destination_type = "linear"

    def send(self, payload: dict[str, Any], config: dict[str, Any]) -> SendResult:
        logger.info(
            "Linear stub: would create issue in team %s for finding %s",
            config.get("team_id", "?"),
            payload.get("finding_id", "?"),
        )
        return SendResult(success=True)

    def test(self) -> TestResult:
        return TestResult(ok=True)
