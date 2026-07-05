"""GraphQL resolver for the integrations catalog.

Mirrors the dataclass-backed catalog at `src.connectors.wizards.catalog.CATALOG`.
Gated on `VIEW_SETTINGS` — same as the REST equivalent.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Optional

import strawberry

from src.connectors.wizards.catalog import CATALOG, ConnectorType as _ConnectorType


@strawberry.type
class ConfigField:
    name: str
    label: str
    field_type: str
    required: bool
    placeholder: str
    options: list[str]
    secret: bool


@strawberry.type
class ConnectorType:
    id: str
    name: str
    description: str
    category: str
    icon_slug: str
    version: str
    status: str
    enterprise_only: bool
    config_fields: list[ConfigField]
    docs_url: str
    href: Optional[str]


@strawberry.type
class IntegrationsCatalog:
    connectors: list[ConnectorType]
    total: int


def _to_gql(entry: _ConnectorType) -> ConnectorType:
    raw = asdict(entry)
    return ConnectorType(
        id=raw["id"],
        name=raw["name"],
        description=raw["description"],
        category=raw["category"],
        icon_slug=raw["icon_slug"],
        version=raw["version"],
        status=raw["status"],
        enterprise_only=raw["enterprise_only"],
        config_fields=[
            ConfigField(
                name=f["name"],
                label=f["label"],
                field_type=f["field_type"],
                required=f["required"],
                placeholder=f["placeholder"],
                options=list(f["options"] or []),
                secret=f["secret"],
            )
            for f in raw["config_fields"]
        ],
        docs_url=raw["docs_url"],
        href=raw["href"],
    )


def integrations_catalog() -> IntegrationsCatalog:
    """Return the static connector catalog. Auth-gated by the schema layer."""
    return IntegrationsCatalog(
        connectors=[_to_gql(c) for c in CATALOG],
        total=len(CATALOG),
    )
