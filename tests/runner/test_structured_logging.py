"""Tests for runner structured JSON logging (Phase 35).

All tests are unit-level and require no external services.
"""
from __future__ import annotations

import json
import logging
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)

from runner.observability.logging import (
    JsonFormatter,
    configure_logging,
    install_json_logging,
    log_with_context,
)


# ---------------------------------------------------------------------------
# JsonFormatter
# ---------------------------------------------------------------------------

def _make_record(msg: str, level: int = logging.INFO, name: str = "test.logger") -> logging.LogRecord:
    record = logging.LogRecord(
        name=name,
        level=level,
        pathname="",
        lineno=0,
        msg=msg,
        args=(),
        exc_info=None,
    )
    return record


class TestJsonFormatter:
    def test_output_is_valid_json(self):
        formatter = JsonFormatter(agent_id="agent-test")
        record = _make_record("hello world")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_required_fields_present(self):
        formatter = JsonFormatter(agent_id="agent-test")
        record = _make_record("hello world")
        parsed = json.loads(formatter.format(record))
        assert "ts" in parsed
        assert "level" in parsed
        assert "msg" in parsed
        assert "logger" in parsed
        assert "agent_id" in parsed
        assert "hostname" in parsed

    def test_msg_content(self):
        formatter = JsonFormatter(agent_id="agent-abc")
        record = _make_record("scanning repo")
        parsed = json.loads(formatter.format(record))
        assert parsed["msg"] == "scanning repo"

    def test_agent_id_from_constructor(self):
        formatter = JsonFormatter(agent_id="runner-custom-001")
        record = _make_record("test")
        parsed = json.loads(formatter.format(record))
        assert parsed["agent_id"] == "runner-custom-001"

    def test_agent_id_from_env(self, monkeypatch):
        monkeypatch.setenv("RUNNER_AGENT_ID", "runner-env-99")
        formatter = JsonFormatter()
        record = _make_record("test")
        parsed = json.loads(formatter.format(record))
        assert parsed["agent_id"] == "runner-env-99"

    def test_extra_context_merged_into_payload(self):
        formatter = JsonFormatter(agent_id="agent-x")
        record = _make_record("job started")
        record._extra = {"job_id": "abc123", "scanner_type": "dependencies_scanning"}
        parsed = json.loads(formatter.format(record))
        assert parsed["job_id"] == "abc123"
        assert parsed["scanner_type"] == "dependencies_scanning"

    def test_exception_included_when_present(self):
        formatter = JsonFormatter(agent_id="agent-x")
        try:
            raise ValueError("boom")
        except ValueError:
            import sys as _sys
            exc_info = _sys.exc_info()
        record = _make_record("something failed")
        record.exc_info = exc_info
        parsed = json.loads(formatter.format(record))
        assert "exception" in parsed
        assert "boom" in parsed["exception"]

    def test_level_field_reflects_log_level(self):
        formatter = JsonFormatter(agent_id="agent-x")
        record = _make_record("warn msg", level=logging.WARNING)
        parsed = json.loads(formatter.format(record))
        assert parsed["level"] == "WARNING"

    def test_logger_name_preserved(self):
        formatter = JsonFormatter(agent_id="agent-x")
        record = _make_record("msg", name="runner.agent")
        parsed = json.loads(formatter.format(record))
        assert parsed["logger"] == "runner.agent"

    def test_ts_is_iso8601_utc(self):
        from datetime import datetime, timezone
        formatter = JsonFormatter(agent_id="agent-x")
        record = _make_record("check ts")
        parsed = json.loads(formatter.format(record))
        # Should parse without raising
        dt = datetime.fromisoformat(parsed["ts"])
        assert dt.tzinfo is not None

    def test_output_is_single_line(self):
        formatter = JsonFormatter(agent_id="agent-x")
        record = _make_record("single line check")
        output = formatter.format(record)
        assert "\n" not in output


# ---------------------------------------------------------------------------
# install_json_logging
# ---------------------------------------------------------------------------

class TestInstallJsonLogging:
    def test_installs_json_handler(self):
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        try:
            install_json_logging()
            assert len(root.handlers) == 1
            assert isinstance(root.handlers[0].formatter, JsonFormatter)
        finally:
            # Restore original handlers
            for h in list(root.handlers):
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)

    def test_idempotent_does_not_stack_handlers(self):
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        try:
            install_json_logging()
            install_json_logging()
            assert len(root.handlers) == 1
        finally:
            for h in list(root.handlers):
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)

    def test_sets_log_level(self):
        root = logging.getLogger()
        original_level = root.level
        original_handlers = list(root.handlers)
        try:
            install_json_logging(level=logging.DEBUG)
            assert root.level == logging.DEBUG
        finally:
            root.setLevel(original_level)
            for h in list(root.handlers):
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)


# ---------------------------------------------------------------------------
# configure_logging
# ---------------------------------------------------------------------------

class TestConfigureLogging:
    def test_json_format_installs_json_formatter(self, monkeypatch):
        monkeypatch.setenv("RUNNER_LOG_FORMAT", "json")
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        try:
            configure_logging()
            assert any(isinstance(h.formatter, JsonFormatter) for h in root.handlers)
        finally:
            for h in list(root.handlers):
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)

    def test_plain_format_does_not_install_json_formatter(self, monkeypatch):
        monkeypatch.setenv("RUNNER_LOG_FORMAT", "plain")
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        try:
            configure_logging()
            assert not any(isinstance(h.formatter, JsonFormatter) for h in root.handlers)
        finally:
            for h in list(root.handlers):
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)

    def test_default_is_json(self, monkeypatch):
        monkeypatch.delenv("RUNNER_LOG_FORMAT", raising=False)
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        try:
            configure_logging()
            assert any(isinstance(h.formatter, JsonFormatter) for h in root.handlers)
        finally:
            for h in list(root.handlers):
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)


# ---------------------------------------------------------------------------
# log_with_context
# ---------------------------------------------------------------------------

class TestLogWithContext:
    def test_emits_context_as_extra_fields(self):
        """log_with_context attaches kwargs as _extra on the record."""
        captured = []

        class CapturingHandler(logging.Handler):
            def emit(self, record):
                captured.append(record)

        test_logger = logging.getLogger("test.log_with_context")
        test_logger.setLevel(logging.DEBUG)
        handler = CapturingHandler()
        test_logger.addHandler(handler)
        test_logger.propagate = False
        try:
            log_with_context(test_logger, logging.INFO, "job assigned", job_id="jj1", scanner_type="secret_scanning")
            assert len(captured) == 1
            record = captured[0]
            assert hasattr(record, "_extra")
            assert record._extra["job_id"] == "jj1"
            assert record._extra["scanner_type"] == "secret_scanning"
            assert record.getMessage() == "job assigned"
        finally:
            test_logger.removeHandler(handler)
            test_logger.propagate = True

    def test_context_appears_in_json_output(self):
        """When used with JsonFormatter, context fields appear in JSON."""
        formatter = JsonFormatter(agent_id="agent-test")
        test_logger = logging.getLogger("test.json_ctx")
        test_logger.setLevel(logging.DEBUG)
        captured = []

        class CapturingHandler(logging.Handler):
            def emit(self, record):
                captured.append(self.format(record))

        handler = CapturingHandler()
        handler.setFormatter(formatter)
        test_logger.addHandler(handler)
        test_logger.propagate = False
        try:
            log_with_context(test_logger, logging.INFO, "heartbeat", in_flight=3, processed=42)
            assert len(captured) == 1
            parsed = json.loads(captured[0])
            assert parsed["in_flight"] == 3
            assert parsed["processed"] == 42
        finally:
            test_logger.removeHandler(handler)
            test_logger.propagate = True
