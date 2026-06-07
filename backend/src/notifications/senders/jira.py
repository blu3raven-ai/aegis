"""Jira sender stub — logs findings; real API integration is a future phase."""
from __future__ import annotations
import logging
from typing import Any
from src.notifications.senders.base import BaseSender, SendResult

logger = logging.getLogger(__name__)


class JiraSender(BaseSender):
    destination_type = "jira"

    def send(self, payload: dict[str, Any], config: dict[str, Any]) -> SendResult:
        logger.info(
            "Jira stub: would create issue in project %s for finding %s",
            config.get("project_key", "?"),
            payload.get("finding_id", "?"),
        )
        return SendResult(success=True)
