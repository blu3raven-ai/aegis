"""Jira sender stub — logs findings; real API integration is a future phase."""
from __future__ import annotations
import logging
from typing import Any

from src.connectors.base import BaseSender, SendResult, TestResult
from src.connectors.registry import register_connector

logger = logging.getLogger(__name__)


@register_connector
class JiraSender(BaseSender):
    id = "jira"
    name = "Jira"
    category = "notification"
    description = "Open Jira tickets for new findings (stub)"
    version = "v0.5"
    status = "beta"
    icon_slug = "jira"
    href = "/notifications"

    destination_type = "jira"

    def send(self, payload: dict[str, Any], config: dict[str, Any]) -> SendResult:
        logger.info(
            "Jira stub: would create issue in project %s for finding %s",
            config.get("project_key", "?"),
            payload.get("finding_id", "?"),
        )
        return SendResult(success=True)

    def test(self) -> TestResult:
        return TestResult(ok=True)
