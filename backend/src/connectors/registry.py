"""Connector registry — classes self-register via the @register_connector decorator."""
from __future__ import annotations

from typing import TypeVar

from src.connectors.base import BaseConnector

_REGISTRY: dict[str, type[BaseConnector]] = {}

T = TypeVar("T", bound=type[BaseConnector])


def register_connector(cls: T) -> T:
    """Class decorator: register a BaseConnector subclass by its declared `id`.

    Raises ValueError if the id is already registered — protects against
    accidentally shadowing an existing connector when two modules collide.
    """
    if cls.id in _REGISTRY:
        raise ValueError(f"Duplicate connector id: {cls.id}")
    _REGISTRY[cls.id] = cls
    return cls


def get_connector(connector_id: str) -> type[BaseConnector]:
    """Look up a registered connector class by id. Raises KeyError if unknown."""
    return _REGISTRY[connector_id]


def all_connectors() -> list[type[BaseConnector]]:
    """All registered connector classes, in insertion order."""
    return list(_REGISTRY.values())


def _reset_registry() -> None:
    """Test-only — empty the registry. Production code never calls this."""
    _REGISTRY.clear()
