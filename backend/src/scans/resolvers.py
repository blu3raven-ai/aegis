"""GraphQL resolvers for the scans surface — severity counts per scanner.

One function per scanner type (dependencies, code, container, secret, iac);
each returns the open-finding severity counts for the caller's assets and
is wired into the matching sub-namespace in ``src.graphql.schema``.
"""
from __future__ import annotations

from typing import Any

from src.graphql.types import SeverityCounts
from src.shared.home_views import get_severity_counts_by_asset_ids


def dependencies_scanning_counts(*, asset_ids: list[str], info_context: dict[str, Any]) -> SeverityCounts:
    counts = get_severity_counts_by_asset_ids(asset_ids, tool="dependencies_scanning", state="open")
    return SeverityCounts(
        total=counts["total"], critical=counts["critical"],
        high=counts["high"], medium=counts["medium"], low=counts["low"],
    )


def code_scanning_counts(*, asset_ids: list[str], info_context: dict[str, Any]) -> SeverityCounts:
    counts = get_severity_counts_by_asset_ids(asset_ids, tool="code_scanning", state="open")
    return SeverityCounts(
        total=counts["total"], critical=counts["critical"],
        high=counts["high"], medium=counts["medium"], low=counts["low"],
    )


def container_scanning_counts(*, asset_ids: list[str], info_context: dict[str, Any]) -> SeverityCounts:
    counts = get_severity_counts_by_asset_ids(asset_ids, tool="container_scanning", state="open")
    return SeverityCounts(
        total=counts["total"], critical=counts["critical"],
        high=counts["high"], medium=counts["medium"], low=counts["low"],
    )


def secret_scanning_counts(*, asset_ids: list[str], info_context: dict[str, Any]) -> SeverityCounts:
    counts = get_severity_counts_by_asset_ids(asset_ids, tool="secret_scanning", state="open")
    return SeverityCounts(
        total=counts["total"], critical=counts["critical"],
        high=counts["high"], medium=counts["medium"], low=counts["low"],
    )


def iac_scanning_counts(*, asset_ids: list[str], info_context: dict[str, Any]) -> SeverityCounts:
    counts = get_severity_counts_by_asset_ids(asset_ids, tool="iac_scanning", state="open")
    return SeverityCounts(
        total=counts["total"], critical=counts["critical"],
        high=counts["high"], medium=counts["medium"], low=counts["low"],
    )


def agent_scanning_counts(*, asset_ids: list[str], info_context: dict[str, Any]) -> SeverityCounts:
    counts = get_severity_counts_by_asset_ids(asset_ids, tool="agent_scanning", state="open")
    return SeverityCounts(
        total=counts["total"], critical=counts["critical"],
        high=counts["high"], medium=counts["medium"], low=counts["low"],
    )
