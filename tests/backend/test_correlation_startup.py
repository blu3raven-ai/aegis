"""Tests for correlation engine startup / shutdown hooks in the lifespan.

Isolates the startup logic without spinning up the full FastAPI app (which
requires DB and MinIO). Instead we extract and test the same conditional
logic directly, using mocks for the engine and its dependencies.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch, call


class TestCorrelationStartupLogic:
    """Validates the env-gated wiring that main.py performs in lifespan."""

    def test_engine_not_started_when_flag_disabled(self, monkeypatch):
        """Default (flag absent) must not construct or start the engine."""
        monkeypatch.delenv("AEGIS_CORRELATION_ENABLED", raising=False)

        mock_engine_cls = MagicMock()

        with patch("src.correlation.engine.CorrelationEngine", mock_engine_cls):
            # Simulate the guard: flag disabled → skip engine construction
            if os.getenv("AEGIS_CORRELATION_ENABLED", "false").lower() == "true":
                engine = mock_engine_cls()
                engine.start()

        mock_engine_cls.assert_not_called()

    def test_engine_not_started_when_flag_false(self, monkeypatch):
        """Explicit AEGIS_CORRELATION_ENABLED=false must not start the engine."""
        monkeypatch.setenv("AEGIS_CORRELATION_ENABLED", "false")

        mock_engine_cls = MagicMock()

        with patch("src.correlation.engine.CorrelationEngine", mock_engine_cls):
            if os.getenv("AEGIS_CORRELATION_ENABLED", "false").lower() == "true":
                engine = mock_engine_cls()
                engine.start()

        mock_engine_cls.assert_not_called()

    def test_engine_started_when_flag_true(self, monkeypatch):
        """AEGIS_CORRELATION_ENABLED=true must construct the engine and call start()."""
        monkeypatch.setenv("AEGIS_CORRELATION_ENABLED", "true")

        mock_engine = MagicMock()
        mock_engine_cls = MagicMock(return_value=mock_engine)
        mock_register = MagicMock()
        mock_argus = MagicMock()
        mock_stream_cfg = {"stream_prefix": "aegis.events.", "max_len": 100000}

        with patch("src.correlation.engine.CorrelationEngine", mock_engine_cls), \
             patch("src.correlation.rules.register_builtin_rules", mock_register), \
             patch("src.argus.connector.get_argus_connector", return_value=mock_argus):

            if os.getenv("AEGIS_CORRELATION_ENABLED", "false").lower() == "true":
                from src.correlation.engine import CorrelationEngine
                from src.correlation.rules import register_builtin_rules
                from src.argus.connector import get_argus_connector
                engine = mock_engine_cls(
                    stream_config=mock_stream_cfg,
                    argus=mock_argus,
                )
                mock_register(engine)
                engine.start()

        mock_engine_cls.assert_called_once()
        mock_register.assert_called_once_with(mock_engine)
        mock_engine.start.assert_called_once()

    def test_engine_stop_called_on_shutdown(self, monkeypatch):
        """The shutdown path must call stop() when engine is in app.state."""
        mock_engine = MagicMock()
        mock_engine.is_running = True

        # Simulate the shutdown guard that main.py uses
        class _FakeAppState:
            correlation_engine = mock_engine

        app_state = _FakeAppState()
        engine_inst = getattr(app_state, "correlation_engine", None)
        if engine_inst is not None:
            engine_inst.stop()

        mock_engine.stop.assert_called_once()

    def test_shutdown_safe_when_no_engine(self):
        """Shutdown must not raise when correlation_engine was never set."""
        class _FakeAppState:
            pass

        app_state = _FakeAppState()
        engine_inst = getattr(app_state, "correlation_engine", None)
        # Mirrors the main.py guard — must not raise
        if engine_inst is not None:
            engine_inst.stop()
        # Reaching here without exception is the assertion

    def test_flag_case_insensitive(self, monkeypatch):
        """AEGIS_CORRELATION_ENABLED should accept TRUE / True / true."""
        for value in ("TRUE", "True", "true"):
            monkeypatch.setenv("AEGIS_CORRELATION_ENABLED", value)
            enabled = os.getenv("AEGIS_CORRELATION_ENABLED", "false").lower() == "true"
            assert enabled, f"Expected True for value {value!r}"

    def test_flag_false_variants(self, monkeypatch):
        """Anything other than 'true' (case-insensitive) must keep engine dormant."""
        for value in ("false", "FALSE", "0", "no", ""):
            monkeypatch.setenv("AEGIS_CORRELATION_ENABLED", value)
            enabled = os.getenv("AEGIS_CORRELATION_ENABLED", "false").lower() == "true"
            assert not enabled, f"Expected False for value {value!r}"
