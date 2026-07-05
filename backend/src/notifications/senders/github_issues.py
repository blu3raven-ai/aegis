"""GitHub Issues sender stub — logs findings; real API integration is a future phase."""
from __future__ import annotations
import logging
from typing import Any

from src.connectors.base import BaseSender, SendResult, TestResult
from src.connectors.registry import register_connector

logger = logging.getLogger(__name__)


@register_connector
class GitHubIssuesSender(BaseSender):
    id = "github-issues"
    name = "GitHub Issues"
    category = "notification"
    description = "Open GitHub issues for new findings (stub)"
    version = "v0.5"
    status = "beta"
    icon_slug = "github"
    href = "/notifications"

    destination_type = "github_issues"

    def send(self, payload: dict[str, Any], config: dict[str, Any]) -> SendResult:
        logger.info(
            "GitHub Issues stub: would open issue in %s for finding %s",
            config.get("repo", "?"),
            payload.get("finding_id", "?"),
        )
        return SendResult(success=True)

    def test(self) -> TestResult:
        return TestResult(ok=True)
