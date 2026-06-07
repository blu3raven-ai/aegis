"""GitHub Issues sender stub — logs findings; real API integration is a future phase."""
from __future__ import annotations
import logging
from typing import Any
from src.notifications.senders.base import BaseSender, SendResult

logger = logging.getLogger(__name__)


class GitHubIssuesSender(BaseSender):
    destination_type = "github_issues"

    def send(self, payload: dict[str, Any], config: dict[str, Any]) -> SendResult:
        logger.info(
            "GitHub Issues stub: would open issue in %s for finding %s",
            config.get("repo", "?"),
            payload.get("finding_id", "?"),
        )
        return SendResult(success=True)
