from __future__ import annotations

import pytest

from src.connectors.base import BaseSender, TestResult
from src.connectors.registry import (
    register_connector,
    get_connector,
    all_connectors,
    _reset_registry,
)


@pytest.fixture(autouse=True)
def clean_registry():
    """Each test starts with an empty registry."""
    _reset_registry()
    yield
    _reset_registry()


def _make_sender(connector_id: str):
    """Helper: build a minimal valid BaseSender subclass."""
    @register_connector
    class FakeSender(BaseSender):
        id = connector_id
        name = connector_id.title()
        category = "notification"
        description = "fake"
        version = "v0.1"
        status = "preview"
        icon_slug = connector_id

        def send(self, payload: dict) -> dict:
            return payload

        def test(self) -> TestResult:
            return TestResult(ok=True)

    return FakeSender


def test_register_then_lookup_returns_class():
    cls = _make_sender("alpha")
    assert get_connector("alpha") is cls


def test_register_duplicate_id_raises():
    _make_sender("dup")
    with pytest.raises(ValueError, match="Duplicate connector id: dup"):
        _make_sender("dup")


def test_all_connectors_returns_registered():
    a = _make_sender("a")
    b = _make_sender("b")
    registered = all_connectors()
    assert a in registered
    assert b in registered
    assert len(registered) == 2


def test_get_unknown_connector_raises_keyerror():
    with pytest.raises(KeyError):
        get_connector("does-not-exist")
