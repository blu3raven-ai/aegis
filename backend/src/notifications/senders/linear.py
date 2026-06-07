"""Linear sender stub — logs findings; real API integration is a future phase."""
from __future__ import annotations
import logging
from typing import Any
from src.notifications.senders.base import BaseSender, SendResult

logger = logging.getLogger(__name__)


class LinearSender(BaseSender):
    destination_type = "linear"

    def send(self, payload: dict[str, Any], config: dict[str, Any]) -> SendResult:
        logger.info(
            "Linear stub: would create issue in team %s for finding %s",
            config.get("team_id", "?"),
            payload.get("finding_id", "?"),
        )
        return SendResult(success=True)
