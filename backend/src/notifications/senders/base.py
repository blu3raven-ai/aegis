"""Base sender contract shared by all destination-type implementations."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class SendResult:
    """Outcome of a single send attempt."""
    success: bool
    response_code: int | None = None
    error: str | None = None


class BaseSender(ABC):
    """Common interface for Slack, generic webhook, and email senders.

    Each implementation receives the formatted payload dict (output of
    formatter.format_for_*) and the destination config dict.
    """

    @abstractmethod
    def send(
        self,
        payload: dict[str, Any],
        config: dict[str, Any],
    ) -> SendResult:
        """Dispatch payload to the external destination described by config.

        Must never raise — all exceptions should be caught and returned as
        SendResult(success=False, error=...).
        """
