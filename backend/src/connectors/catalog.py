"""Serialize the connector registry into the catalog payload served at /api/v1/connectors."""
from __future__ import annotations

from src.connectors.registry import all_connectors


def serialize_catalog() -> list[dict]:
    """Walk the registry and emit one metadata dict per registered connector.

    Shape:
        {id, name, kind, category, description, version, status, icon_slug, href}
    """
    return [
        {
            "id": c.id,
            "name": c.name,
            "kind": c.kind,
            "category": c.category,
            "description": c.description,
            "version": c.version,
            "status": c.status,
            "icon_slug": c.icon_slug,
            "href": c.href,
        }
        for c in all_connectors()
    ]
