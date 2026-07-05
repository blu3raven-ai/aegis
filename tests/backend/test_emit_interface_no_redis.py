"""Regression guard: EmitInterface no longer requires a Redis client."""
import inspect
import sys
import types
from unittest.mock import MagicMock


def _stub_missing_modules():
    """Stub out modules that are absent in this test environment so the import
    of emit_interface succeeds without a full application stack."""
    stubs = {
        "src.shared.event_types": types.ModuleType("src.shared.event_types"),
        "src.shared.event_types.finding": types.ModuleType("src.shared.event_types.finding"),
        "src.correlation.chain_graph_store": types.ModuleType("src.correlation.chain_graph_store"),
    }
    for name, mod in stubs.items():
        if name not in sys.modules:
            # Provide dummy classes for anything emit_interface imports by name
            for attr in (
                "ChainCreatedEvent", "ChainUpdatedEvent",
                "FindingClosedEvent", "FindingCreatedEvent", "FindingSeverityChangedEvent",
                "ChainGraphStore",
            ):
                setattr(mod, attr, MagicMock)
            sys.modules[name] = mod


_stub_missing_modules()

from src.correlation.emit_interface import EmitInterface  # noqa: E402


def test_emit_interface_constructor_has_no_redis_param():
    sig = inspect.signature(EmitInterface.__init__)
    assert "redis_client" not in sig.parameters
    assert "redis" not in sig.parameters
