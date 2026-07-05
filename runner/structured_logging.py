# runner/structured_logging.py
"""Structured JSON logging for the runner agent.

Enabled by default (RUNNER_LOG_FORMAT=json).
Set RUNNER_LOG_FORMAT=plain for human-readable output during local development.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import time
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """Renders log records as single-line JSON with consistent fields."""

    def __init__(self, agent_id: str | None = None):
        super().__init__()
        self.agent_id = agent_id or os.getenv("RUNNER_AGENT_ID", f"runner-{socket.gethostname()}")
        self.hostname = socket.gethostname()

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
        }
        # Pull anything user-attached via logging extra=
        if hasattr(record, "_extra"):
            payload.update(record._extra)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def install_json_logging(level: int = logging.INFO) -> None:
    """Replace existing handlers with a JsonFormatter handler. Idempotent."""
    root = logging.getLogger()
    root.setLevel(level)
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    # Remove existing handlers so this is safe to call multiple times
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)


def configure_logging() -> None:
    """Install JSON or plain logging based on RUNNER_LOG_FORMAT env var."""
    fmt = os.getenv("RUNNER_LOG_FORMAT", "json").lower()
    root = logging.getLogger()
    if fmt == "plain":
        # Remove existing handlers so we get a clean plain formatter regardless
        # of what previous calls may have installed.
        for h in list(root.handlers):
            root.removeHandler(h)
        root.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s — %(message)s")
        )
        root.addHandler(handler)
    else:
        install_json_logging()


def log_with_context(logger: logging.Logger, level: int, msg: str, **context) -> None:
    """Emit a log record with structured context attached as JSON fields."""
    record = logger.makeRecord(logger.name, level, "", 0, msg, (), None)
    record._extra = context  # type: ignore[attr-defined]
    logger.handle(record)
